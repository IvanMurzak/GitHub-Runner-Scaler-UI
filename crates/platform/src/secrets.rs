// owner: d2-machine-secret-store

//! The one persisted GitHub credential, in a place a boot-time service can
//! read.
//!
//! `07-security.md` counts the persisted credential surface and gets to one:
//! *"The product now holds exactly one persisted GitHub credential and one
//! short-lived sensitive value."* This module is where that one credential
//! lives. The short-lived one — the encoded JIT configuration — belongs to
//! [`crate::process::RestrictiveHandoff`] and is not stored here or anywhere
//! else.
//!
//! # The constraint that decides the whole design
//!
//! D13 requires the service to start at **machine boot**.
//! `05-infrastructure.md`: *"A boot-time service runs outside any user's login
//! session and cannot read a per-user keychain on any supported OS: macOS
//! LaunchAgents start only at login, and Windows Credential Manager vaults are
//! per-user."* So the default store is machine-scoped, and every per-user
//! secret facility on all three operating systems is unavailable to it by
//! construction rather than by preference.
//!
//! | OS | [`SecretScope::Machine`] | [`SecretScope::User`] |
//! |---|---|---|
//! | Windows | DPAPI **machine** scope, in a file under `%ProgramData%` with its own protected DACL | DPAPI **user** scope, in a file under `%LOCALAPPDATA%` with its own protected DACL |
//! | macOS | System Keychain (`/Library/Keychains/System.keychain`) | the account's login keychain |
//! | Linux | `0600` file under `/var/lib/runner-manager`, plus the systemd credential the service is started with | `0600` file under `$XDG_DATA_HOME/runner-manager` |
//!
//! `service install --start-at login` is the escape hatch
//! `07-security.md` promises operators who reject machine-scoped storage:
//! *"Operators who reject this can use `service install --start-at login` and
//! keep a user-scoped store, accepting no unattended restart."* Both columns
//! implement [`SecretStore`], the active one is chosen by
//! [`SecretScope::for_start_mode`], and [`ActiveStore`] is what `host show`
//! and `service status` print so the choice is inspectable rather than
//! implied.
//!
//! # The accepted trade-off, implemented honestly
//!
//! A local administrator or `root` on this machine can read a machine-scoped
//! secret. `07-security.md` records that as an accepted consequence, on the
//! grounds that such an account *"can already read the runner's own
//! credentials and job workspaces"*. Nothing here tries to defeat it, and
//! nothing here pretends to. What is defended is the case that is actually in
//! the threat model: **an ordinary local user who is not an administrator must
//! not be able to read the stored value**, and [`SecretStore::protection`]
//! reports whether that holds, per OS, through the one cross-platform name
//! [`crate::process::permissions_summary`] already defines.
//!
//! Delete is delete, not erasure. [`crate::process::RestrictiveHandoff`] sets
//! out why no userspace program can promise that the bytes are unrecoverable —
//! a journal, a snapshot, or an SSD's wear levelling each keep copies an
//! overwrite never reaches — and the same disclaimer applies here. The Linux
//! backend overwrites before unlinking because the value is at rest in
//! plaintext there and the overwrite is free; that is a best effort and is not
//! a claim.
//!
//! # What never holds this value
//!
//! SQLite, TOML configuration, logs, diagnostics, UI state, and command-line
//! arguments. The type system carries as much of that as it can: the value
//! crosses this module's surface only as a [`SecretString`], which has no
//! `Display` and a redacting `Debug`, and no error in [`SecretStoreError`]
//! carries the value or any part of it. `client_id` is public by design
//! (`07-security.md`: *"Public by design; may appear in logs and
//! documentation"*) and is not a secret this store handles.
//!
//! # Blocking, not async
//!
//! DPAPI, Security.framework and `open(2)` are blocking calls that take
//! microseconds. This runs twice in the life of a process — once at `auth
//! login`, once at startup — so an async surface would buy nothing and would
//! oblige every caller to be in a runtime to read a file.
//!
//! # Where a test may point it, and where it may not
//!
//! [`PlatformSecretStore::standard`] resolves the production location in the
//! table above. [`PlatformSecretStore::rooted_at`] puts the same backend under
//! a directory the caller names, exactly as
//! [`crate::paths::AppPaths::rooted_at`] does for the four application-data
//! directories, and for the same two reasons: a test needs a disposable store,
//! and a service installed against an explicitly configured root has to
//! reproduce one.
//!
//! **No test in this crate writes to a standard location**, and that is a
//! deliberate constraint rather than an oversight. Two of the six standard
//! locations need `root` to create (`/var/lib`, the System Keychain), and the
//! other four are the operator's real store — a suite that wrote there would
//! destroy a developer's `auth login` every time it ran. So the standard
//! locations are asserted by *resolution*, and every round trip runs against a
//! rooted store. What that does and does not cover is written out at
//! [`PlatformSecretStore::rooted_at`].

use std::fmt;
use std::path::{Path, PathBuf};

use runner_manager_domain::model::StartMode;
use secrecy::{ExposeSecret, SecretString};

/// The product identity, resolved from the one place that defines it.
///
/// `crate::paths` owns these three segments and builds the four
/// application-data directories out of them. This module builds *different*
/// locations — `%ProgramData%\<org>\<app>`, `$XDG_DATA_HOME/<app>`, the macOS
/// keychain service — but out of the same identity, and it must stay the same
/// identity. Spelled a second time here, a drift would move the secret store
/// out from under an upgraded binary and the token would read as simply
/// absent, which is the one failure mode this store must never produce
/// silently.
use crate::paths::{APPLICATION, ORGANIZATION, QUALIFIER};

/// Reverse-domain service name for the macOS keychain item.
///
/// Composed rather than written out, for the reason above. It is a `LazyLock`
/// because the three segments are `const`s and neither `concat!` nor a `const
/// fn` can join them — `concat!` takes literals, not constant items. The
/// composition is asserted against the documented literal by
/// `the_standard_locations_are_the_documented_ones`, which keeps its own
/// hard-coded strings precisely so that it is an *independent* oracle rather
/// than a second copy of this expression.
#[cfg(target_os = "macos")]
static KEYCHAIN_SERVICE: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(|| format!("{QUALIFIER}.{ORGANIZATION}.{APPLICATION}"));

/// The keychain account, and the stem of the file name on the two platforms
/// that use a file. One value, one name, everywhere.
const ITEM: &str = "user-access-token";

/// The directory a file-backed store keeps its value in, under whichever root
/// the scope resolved to. Never `config/` — `05-infrastructure.md` reserves
/// that for *"non-secret TOML and SQLite"*.
const DIRECTORY: &str = "secrets";

// ---------------------------------------------------------------------------
// Scope
// ---------------------------------------------------------------------------

/// Which of the two stores a value lives in.
///
/// Not a preference and not a tuning knob: it is a direct function of the
/// service's start mode, because a service that starts at boot has no login
/// session to read a user-scoped store from. [`SecretScope::for_start_mode`]
/// is that function, and it is total in both directions —
/// [`SecretScope::start_mode`] is its inverse, which is what lets
/// [`ActiveStore`] state whether the store in use agrees with the start mode
/// actually configured.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SecretScope {
    /// Readable by a service running at machine boot, outside any login
    /// session. The default, and what `--start-at boot` requires.
    Machine,
    /// Readable only inside the operator's login session. What
    /// `--start-at login` gets, at the cost of no unattended restart.
    User,
}

impl SecretScope {
    /// The store a given start mode obliges.
    #[must_use]
    pub const fn for_start_mode(mode: StartMode) -> Self {
        match mode {
            StartMode::Boot => Self::Machine,
            StartMode::Login => Self::User,
        }
    }

    /// The start mode this store is the one correct choice for.
    #[must_use]
    pub const fn start_mode(self) -> StartMode {
        match self {
            Self::Machine => StartMode::Boot,
            Self::User => StartMode::Login,
        }
    }

    /// The name `host show`, `service status`, and the `scope` log field use.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Machine => "machine",
            Self::User => "user",
        }
    }
}

impl fmt::Display for SecretScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Something went wrong reaching the secret store.
///
/// **No variant carries the stored value, and none ever may.** Every one of
/// them is formatted into an operator-facing message and into a `tracing`
/// event, and `07-security.md`'s release gate is that the user access token is
/// *"absent from logs, databases, snapshots, crash reports, and CLI output"*.
/// A variant that carried the value would put it in all four at once.
///
/// Note what is *not* here: an "absent" variant. A load that finds nothing is
/// [`Ok(None)`], because absence is the ordinary state of this store before
/// `auth login` and after `auth logout`, and a caller that has to distinguish
/// "not logged in" from "the keychain is unreachable" cannot be asked to do it
/// by matching on an error kind.
#[derive(Debug, thiserror::Error)]
pub enum SecretStoreError {
    /// The store's location could not be worked out at all.
    #[error("cannot work out where the {scope}-scoped secret store lives: {reason}")]
    Resolve {
        /// Which store was being resolved.
        scope: SecretScope,
        /// What was missing, in terms an operator can act on.
        reason: String,
    },

    /// The value could not be written.
    #[error(
        "cannot write the user access token to the {scope}-scoped store at {location}: {source}"
    )]
    Store {
        /// Which store.
        scope: SecretScope,
        /// Where it lives, as [`SecretStore::location`] reports it.
        location: String,
        /// The underlying platform error.
        #[source]
        source: std::io::Error,
    },

    /// The value could not be read back.
    #[error(
        "cannot read the user access token from the {scope}-scoped store at {location}: {source}"
    )]
    Load {
        /// Which store.
        scope: SecretScope,
        /// Where it lives.
        location: String,
        /// The underlying platform error.
        #[source]
        source: std::io::Error,
    },

    /// The value could not be removed.
    ///
    /// Worth an error rather than a shrug, for the reason
    /// `05-infrastructure.md` gives the credential-disclosure response: step 2
    /// is *"Run `auth logout` on every host to purge the machine-scoped secret
    /// store"*, and an operator following that procedure has to be told when a
    /// host did not comply.
    #[error(
        "cannot delete the user access token from the {scope}-scoped store at {location}: {source}"
    )]
    Delete {
        /// Which store.
        scope: SecretScope,
        /// Where it lives.
        location: String,
        /// The underlying platform error.
        #[source]
        source: std::io::Error,
    },

    /// Something is stored, and it is not a value this store wrote.
    ///
    /// Deliberately not folded into [`SecretStoreError::Load`] and deliberately
    /// not reported as absence. A caller that saw absence would silently start
    /// a device-flow login and overwrite whatever is there; a caller that saw a
    /// transient read failure would retry forever. This is neither: it is an
    /// operator-actionable condition whose remedy is `auth logout` followed by
    /// `auth login`.
    #[error(
        "the {scope}-scoped store at {location} does not hold a user access token this product \
         wrote: {detail}. Run `auth logout` to purge it and `auth login` to obtain a fresh token."
    )]
    Corrupt {
        /// Which store.
        scope: SecretScope,
        /// Where it lives.
        location: String,
        /// What is wrong with what is there, in terms that name no part of it.
        /// A byte count is not a disclosure; the bytes would be, so they are
        /// never carried.
        detail: String,
    },

    /// The access control protecting the value could not be read back.
    #[error("cannot inspect what protects the {scope}-scoped store at {}: {source}", guard.display())]
    Inspect {
        /// Which store.
        scope: SecretScope,
        /// The filesystem object whose access control was being read.
        guard: PathBuf,
        /// The underlying error.
        #[source]
        source: crate::process::HandoffError,
    },
}

// ---------------------------------------------------------------------------
// What the operations report
// ---------------------------------------------------------------------------

/// What [`SecretStore::delete`] found.
///
/// Both variants are success. `auth logout` on a host that was never logged in
/// is not a failure, and the credential-disclosure procedure in
/// `05-infrastructure.md` is run across *every* host precisely because the
/// operator does not know which ones hold a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Removal {
    /// A value was there and is not any more.
    Removed,
    /// There was nothing to remove.
    AlreadyAbsent,
}

impl Removal {
    /// Whether this call is the one that removed something.
    #[must_use]
    pub const fn removed_something(self) -> bool {
        matches!(self, Self::Removed)
    }
}

/// What actually stands between the stored value and an ordinary local user.
///
/// The three operating systems protect it with three different mechanisms, so
/// the useful cross-platform question is not "what is the mode" but "**which
/// object's access control decides who can read this, and does it exclude an
/// unprivileged local user**". [`Protection::guard`] answers the first half and
/// [`Protection::readable_by_other_local_users`] the second.
///
/// | store | guard |
/// |---|---|
/// | Windows, either scope | the file holding the DPAPI blob, whose DACL is protected and names no broad trustee |
/// | Linux, either scope | the `0600` file |
/// | macOS, login or rooted keychain | the keychain database file |
/// | macOS, System Keychain | `/var/db/SystemKey`, the root-only master key that unlocks it |
///
/// That last row is the one worth reading twice.
/// `/Library/Keychains/System.keychain` is itself world-readable, and saying so
/// and stopping would be both true and useless: its contents are encrypted, and
/// what decides who can decrypt them is the mode of the master key beside it.
/// Reporting the keychain database there would answer a question nobody asked
/// and would answer it wrongly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Protection {
    guard: PathBuf,
    description: String,
    readable_by_other_local_users: bool,
}

impl Protection {
    /// The filesystem object whose access control was inspected.
    #[must_use]
    pub fn guard(&self) -> &Path {
        &self.guard
    }

    /// The platform's own description of it — a Unix mode, or a DACL in SDDL
    /// form. For diagnostics and for test failure messages.
    #[must_use]
    pub fn description(&self) -> &str {
        &self.description
    }

    /// Whether an ordinary local user other than the owner could read the
    /// stored value.
    ///
    /// A local administrator or `root` is deliberately outside this question;
    /// see this module's documentation and `07-security.md`.
    #[must_use]
    pub const fn readable_by_other_local_users(&self) -> bool {
        self.readable_by_other_local_users
    }
}

impl fmt::Display for Protection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} ({}){}",
            self.guard.display(),
            self.description,
            if self.readable_by_other_local_users {
                " -- READABLE BY OTHER LOCAL USERS"
            } else {
                ""
            }
        )
    }
}

/// Which store is in use, and whether that is the one the configured start
/// mode obliges.
///
/// `05-infrastructure.md` requires the start mode to be visible in `host show`
/// and in TUI host settings, and requires `service status` to say when
/// `--start-at login` means the agent does not run until the operator logs in.
/// This is the value both of those print. It exists as a type rather than as a
/// formatted string in two places so that the two cannot drift.
///
/// [`ActiveStore::agrees_with_start_mode`] is the check worth having: the store
/// a process opened and the start mode recorded for the installed service are
/// two independently persisted facts, and a host whose service was switched
/// from `boot` to `login` without the token being moved is a host whose daemon
/// will start and then fail to find a credential. Saying so in `service status`
/// is cheaper than finding out at three in the morning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveStore {
    scope: SecretScope,
    start_mode: StartMode,
    location: String,
}

impl ActiveStore {
    /// Pairs a store with the start mode currently configured for the service.
    #[must_use]
    pub fn of(store: &dyn SecretStore, start_mode: StartMode) -> Self {
        Self {
            scope: store.scope(),
            start_mode,
            location: store.location(),
        }
    }

    /// The store in use.
    #[must_use]
    pub const fn scope(&self) -> SecretScope {
        self.scope
    }

    /// The start mode configured for the service.
    #[must_use]
    pub const fn start_mode(&self) -> StartMode {
        self.start_mode
    }

    /// Where the store keeps its value, in the platform's own terms.
    #[must_use]
    pub fn location(&self) -> &str {
        &self.location
    }

    /// Whether the store in use is the one this start mode obliges.
    #[must_use]
    pub fn agrees_with_start_mode(&self) -> bool {
        SecretScope::for_start_mode(self.start_mode) == self.scope
    }
}

impl fmt::Display for ActiveStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}-scoped secret store at {} (service starts at {})",
            self.scope, self.location, self.start_mode
        )?;
        if !self.agrees_with_start_mode() {
            write!(
                f,
                " -- MISMATCH: starting at {} needs the {}-scoped store",
                self.start_mode,
                SecretScope::for_start_mode(self.start_mode)
            )?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// The port
// ---------------------------------------------------------------------------

/// Store, load, delete — and say where the value lives and what protects it.
///
/// `Send + Sync` because the agent holds one across `tokio` tasks; `Debug`
/// because every other port in this workspace is, and because a store that
/// could not be printed in an error context would be replaced by a path that
/// could.
pub trait SecretStore: fmt::Debug + Send + Sync {
    /// Which of the two stores this is.
    fn scope(&self) -> SecretScope;

    /// Where the value lives, in the platform's own terms. What `host show`
    /// and `service status` print, and never the value itself.
    fn location(&self) -> String;

    /// Writes the value, replacing whatever was there.
    ///
    /// # Errors
    ///
    /// [`SecretStoreError::Store`].
    fn store(&self, secret: &SecretString) -> Result<(), SecretStoreError>;

    /// Reads the value back, or reports that there is none.
    ///
    /// `Ok(None)` is absence and is not an error; see [`SecretStoreError`].
    ///
    /// # Errors
    ///
    /// [`SecretStoreError::Load`] when the store cannot be reached, and
    /// [`SecretStoreError::Corrupt`] when what is there is not a value this
    /// store wrote.
    fn load(&self) -> Result<Option<SecretString>, SecretStoreError>;

    /// Removes the value.
    ///
    /// # Errors
    ///
    /// [`SecretStoreError::Delete`].
    fn delete(&self) -> Result<Removal, SecretStoreError>;

    /// What stands between the stored value and an ordinary local user.
    ///
    /// # Errors
    ///
    /// [`SecretStoreError::Inspect`].
    fn protection(&self) -> Result<Protection, SecretStoreError>;
}

// ---------------------------------------------------------------------------
// The platform store
// ---------------------------------------------------------------------------

/// The real store: DPAPI on Windows, a keychain on macOS, a `0600` file plus
/// systemd credentials on Linux.
///
/// One type with three bodies rather than three types, because the choice is
/// made by `cfg` at compile time and a caller never has one without the other
/// two being impossible. The scope, by contrast, is a runtime choice and is a
/// field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformSecretStore {
    scope: SecretScope,
    site: sys::Site,
}

impl PlatformSecretStore {
    /// Resolves the platform-standard location for `scope`.
    ///
    /// This is what production uses and what `host show` reports. Nothing is
    /// touched on disk here; the directory, the file, and the keychain are
    /// created by the first [`SecretStore::store`].
    ///
    /// # Errors
    ///
    /// [`SecretStoreError::Resolve`] when the platform cannot say where the
    /// location is — no `%ProgramData%` on Windows, no home directory for this
    /// account on the two Unixes. A service account configured with no profile
    /// is the way that actually happens, and the message says so.
    pub fn standard(scope: SecretScope) -> Result<Self, SecretStoreError> {
        let site = sys::standard_site(scope).map_err(|reason| SecretStoreError::Resolve {
            scope,
            reason: reason.to_string(),
        })?;
        Ok(Self { scope, site })
    }

    /// Resolves the store the configured start mode obliges.
    ///
    /// The one constructor a daemon should use: it makes the store a function
    /// of the recorded start mode rather than of whichever constructor the
    /// call site happened to reach for.
    ///
    /// # Errors
    ///
    /// As [`PlatformSecretStore::standard`].
    pub fn for_start_mode(mode: StartMode) -> Result<Self, SecretStoreError> {
        Self::standard(SecretScope::for_start_mode(mode))
    }

    /// Places the same backend under a root the caller names.
    ///
    /// [`crate::paths::AppPaths::rooted_at`] is the precedent and the reasoning
    /// is the same: a test needs a disposable store, and a service installed
    /// against an explicitly configured root has to reproduce one. A relative
    /// root stays relative, which is the caller's decision to make.
    ///
    /// # What a rooted store does and does not exercise
    ///
    /// Everything that makes a scope a scope, on two of the three platforms.
    /// The Windows backend picks its DPAPI flag and its DACL from the scope,
    /// not from the site, so a rooted machine-scoped store is protected and
    /// encrypted exactly as the standard one is. The Linux backend's `0600`
    /// file, its atomic replace, and its systemd-credential read path are the
    /// same code under either root.
    ///
    /// macOS is where a rooted store is genuinely weaker, and it is worth being
    /// precise about how. A rooted store is a keychain this program creates in
    /// the root directory, and both scopes get one; what the standard sites
    /// have and it does not is the *choice of keychain* — the System Keychain
    /// against the login keychain — and the System Keychain's root-only master
    /// key. The keychain calls themselves, the item, the not-found handling and
    /// the delete are identical. The password protecting a rooted keychain is
    /// [`ROOTED_KEYCHAIN_PASSWORD`], which is a constant in a public binary and
    /// therefore protects nothing on its own: what protects a rooted keychain
    /// is the mode of the directory it is in, which is the same protection the
    /// Linux backend relies on for a value it stores in plaintext.
    ///
    /// # Errors
    ///
    /// [`SecretStoreError::Resolve`]; in practice it cannot fail, because the
    /// caller supplied the root.
    pub fn rooted_at(scope: SecretScope, root: impl AsRef<Path>) -> Result<Self, SecretStoreError> {
        let site =
            sys::rooted_site(scope, root.as_ref()).map_err(|reason| SecretStoreError::Resolve {
                scope,
                reason: reason.to_string(),
            })?;
        Ok(Self { scope, site })
    }

    /// The filesystem object whose access control decides who can read this
    /// store, whether or not anything is stored yet.
    ///
    /// Separate from [`SecretStore::protection`] because the guard can be named
    /// before the store exists, which is what lets `host show` report the
    /// machine store's protection on a host that has never logged in.
    #[must_use]
    pub fn guard(&self) -> PathBuf {
        sys::guard(&self.site)
    }

    /// Turns platform bytes into the value, or says why they are not one.
    fn decode(&self, bytes: Vec<u8>) -> Result<SecretString, SecretStoreError> {
        use secrecy::zeroize::Zeroize as _;

        let length = bytes.len();
        // A zero-length value is not a credential and cannot have been written
        // by `store`, which refuses one. Treating it as absence would hide a
        // truncated write behind a device-flow login.
        if length == 0 {
            return Err(self.corrupt("it is empty"));
        }

        match String::from_utf8(bytes) {
            Ok(text) => Ok(SecretString::from(text)),
            Err(error) => {
                // The bytes are not the value, but they may still be *a* value
                // — something else's, or a partially overwritten one. Scrub the
                // buffer rather than dropping it, and report only its length.
                let mut bytes = error.into_bytes();
                bytes.zeroize();
                Err(self.corrupt(&format!("the {length} bytes there are not valid UTF-8")))
            }
        }
    }

    fn corrupt(&self, detail: &str) -> SecretStoreError {
        SecretStoreError::Corrupt {
            scope: self.scope,
            location: self.location(),
            detail: detail.to_string(),
        }
    }
}

impl SecretStore for PlatformSecretStore {
    fn scope(&self) -> SecretScope {
        self.scope
    }

    fn location(&self) -> String {
        sys::describe(&self.site)
    }

    fn store(&self, secret: &SecretString) -> Result<(), SecretStoreError> {
        let failed = |source| SecretStoreError::Store {
            scope: self.scope,
            location: self.location(),
            source,
        };

        let exposed = secret.expose_secret();
        if exposed.is_empty() {
            // Refused here rather than accepted and stored, because an empty
            // value is indistinguishable from a truncated one on the way back
            // out and `decode` has to reject it either way.
            return Err(failed(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "an empty value is not a user access token",
            )));
        }

        sys::store(&self.site, self.scope, exposed.as_bytes()).map_err(failed)?;

        tracing::info!(
            event = "secret_store_written",
            scope = self.scope.as_str(),
            "the user access token was written to the secret store"
        );
        Ok(())
    }

    fn load(&self) -> Result<Option<SecretString>, SecretStoreError> {
        let bytes = sys::load(&self.site, self.scope).map_err(|source| {
            // A backend reports "there is something here and it is not ours"
            // as `InvalidData` -- a DPAPI blob this machine's key cannot
            // unprotect, a keychain item of the wrong shape. That is the
            // `Corrupt` condition, not a transient read failure, and the
            // difference decides whether a caller retries or tells the
            // operator to run `auth logout`.
            if source.kind() == std::io::ErrorKind::InvalidData {
                self.corrupt(&source.to_string())
            } else {
                SecretStoreError::Load {
                    scope: self.scope,
                    location: self.location(),
                    source,
                }
            }
        })?;

        match bytes {
            Some(bytes) => self.decode(bytes).map(Some),
            None => Ok(None),
        }
    }

    fn delete(&self) -> Result<Removal, SecretStoreError> {
        let removed = sys::delete(&self.site).map_err(|source| SecretStoreError::Delete {
            scope: self.scope,
            location: self.location(),
            source,
        })?;

        let removal = if removed {
            Removal::Removed
        } else {
            Removal::AlreadyAbsent
        };

        tracing::info!(
            event = "secret_store_purged",
            scope = self.scope.as_str(),
            outcome = if removal.removed_something() {
                "removed"
            } else {
                "already_absent"
            },
            "the user access token was purged from the secret store"
        );
        Ok(removal)
    }

    fn protection(&self) -> Result<Protection, SecretStoreError> {
        let guard = sys::guard(&self.site);
        let summary = crate::process::permissions_summary(&guard).map_err(|source| {
            SecretStoreError::Inspect {
                scope: self.scope,
                guard: guard.clone(),
                source,
            }
        })?;

        Ok(Protection {
            guard,
            description: summary.description,
            readable_by_other_local_users: summary.readable_by_other_local_users,
        })
    }
}

/// The password protecting a keychain created by
/// [`PlatformSecretStore::rooted_at`] on macOS.
///
/// A constant in a public binary, and therefore not a secret. It is here
/// because `SecKeychainCreate` requires *a* password and the alternative —
/// passing `NULL` — prompts the operator for one, which a daemon must never
/// do. What protects a rooted keychain is the mode of the directory it is
/// created in; see [`PlatformSecretStore::rooted_at`].
///
/// Public so that a test can assert this is what it is, rather than discovering
/// it by reading the backend.
pub const ROOTED_KEYCHAIN_PASSWORD: &str = "runner-manager-rooted-keychain";

/// The name of the systemd credential the Linux machine-scoped store reads
/// before it reads its own file.
///
/// `05-infrastructure.md` puts the Linux machine store at *"`0600` file plus
/// systemd credentials"*, and the second half is a read path rather than a
/// write path: `systemd` decrypts a credential into a private `ramfs` at
/// `$CREDENTIALS_DIRECTORY` and mounts it read-only, so a service given
/// `LoadCredentialEncrypted=` gets the value without the file ever being
/// readable by anything but that unit. A store that ignored it would oblige an
/// operator who had set one up to keep a second plaintext copy on disk.
pub const SYSTEMD_CREDENTIAL: &str = "runner-manager.user-access-token";

/// The environment variable `systemd` sets for a unit that was given
/// credentials. Read once, at [`PlatformSecretStore::standard`] time.
pub const CREDENTIALS_DIRECTORY: &str = "CREDENTIALS_DIRECTORY";

// ---------------------------------------------------------------------------
// Platform implementations
// ---------------------------------------------------------------------------
//
// Each `sys` module offers the same eight items, and the shared code above is
// the only caller:
//
//   Site                        -- where one store keeps its value
//   standard_site(scope)        -> the production location for that scope
//   rooted_site(scope, root)    -> the same backend under a caller-named root
//   describe(&Site)             -> what `host show` prints
//   guard(&Site)                -> the object whose access control decides
//                                  who can read the value
//   store(&Site, scope, bytes)  -> write, replacing whatever was there
//   load(&Site, scope)          -> Ok(None) when nothing is stored;
//                                  ErrorKind::InvalidData when something is
//                                  stored and it is not ours
//   delete(&Site)               -> Ok(false) when there was nothing to remove
//
// `standard_site` and `rooted_site` fail with a `String` rather than an
// `io::Error`, because a resolution failure is never an `errno`: it is "this
// account has no home directory" or "this Windows reports no %ProgramData%",
// and both want a sentence an operator can act on.

/// The stem every temporary file this module writes shares, so that a crash
/// leaves something [`sweep_temporaries`] can recognise rather than an
/// anonymous file beside the store.
#[cfg(not(target_os = "macos"))]
const TEMP_PREFIX: &str = "user-access-token.";

/// Removes temporary files left in `directory` by an interrupted write.
///
/// Called from `delete` and not from `store`, and that order is deliberate:
/// two `store` calls can be in flight at once and a sweep there could remove a
/// live temporary out from under the other one. `delete` is `auth logout`,
/// which is where "leave no remnant" is the actual requirement.
#[cfg(not(target_os = "macos"))]
fn sweep_temporaries(directory: &Path) {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if name.starts_with(TEMP_PREFIX) && name.ends_with(".tmp") {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

/// Overwrites every byte of a file with zeroes, in place.
///
/// Returns `Ok(false)` when there is nothing there, which is the ordinary state
/// of a store that was never written.
///
/// # What this is and is not
///
/// It is **not** secure erasure and nothing here claims it is. The reasoning is
/// [`crate::process::RestrictiveHandoff`]'s, unchanged: a journal, a
/// copy-on-write snapshot, or an SSD's wear levelling can each keep a copy that
/// an overwrite never reaches. It is here because it costs one `write` and
/// because on Linux the stored value is at rest in **plaintext** — the mode is
/// the whole access control there — so leaving the bytes in the block after the
/// inode is unlinked is worse than not.
///
/// # Why it is a separate function, and not `cfg`-gated to Linux
///
/// Both are the same reason, and it is a testing reason rather than a
/// portability one. Folded into the delete path, the zero fill was asserted by
/// nothing: a test could only observe the file's *absence* afterwards, which is
/// what removing it proves too, so the fill could have been deleted outright
/// and the suite would have stayed green. Split out, the fill is observable —
/// [`tests::overwrite_zeroes_every_byte_and_leaves_the_file_there`] reads the
/// bytes back before anything unlinks them. Compiled on Windows as well as
/// Linux, that test runs on every leg of the matrix rather than on one, and the
/// Windows delete path calls it too: the value there is ciphertext, so the fill
/// buys less, but it costs the same and it keeps the mechanism on a path a
/// developer can execute.
#[cfg(not(target_os = "macos"))]
fn overwrite(path: &Path) -> std::io::Result<bool> {
    use std::io::Write as _;

    let mut file = match std::fs::OpenOptions::new().write(true).open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };

    let length = usize::try_from(file.metadata()?.len()).unwrap_or(0);
    file.write_all(&vec![0u8; length])?;
    file.flush()?;
    file.sync_all()?;
    Ok(true)
}

/// Drops trailing ASCII whitespace from a value that came from outside this
/// module.
///
/// There is exactly one such value: the systemd credential. `store` writes no
/// newline and its own file is read back verbatim, deliberately — trimming
/// there would quietly repair a corruption this store would rather report. A
/// credential, though, is produced by the operator through `systemd-creds
/// encrypt`, and `echo`, `printf '%s\n'`, and every text editor put a newline
/// on the end. Used byte for byte, that newline becomes part of the token and
/// surfaces much later inside an `Authorization` header, where it looks like a
/// bad credential rather than a bad read.
///
/// Trailing only. A token has no interior whitespace, but if one ever did,
/// silently rewriting its middle would be a worse bug than the one this fixes.
#[cfg(not(target_os = "macos"))]
// `allow` rather than `expect`: on Windows this is dead in a normal build and
// live in a test build, because the test below is the whole reason it is
// compiled there, and an `expect` that is fulfilled in only one of the two
// configurations warns in the other.
#[cfg_attr(
    windows,
    allow(
        dead_code,
        reason = "the systemd credential path is Linux-only; this is compiled on Windows so \
                  that its unit test runs on every leg of the matrix rather than on the one \
                  platform a developer usually cannot execute"
    )
)]
fn trim_trailing_ascii_whitespace(mut bytes: Vec<u8>) -> Vec<u8> {
    while bytes.last().is_some_and(u8::is_ascii_whitespace) {
        bytes.pop();
    }
    bytes
}

// ---------------------------------------------------------------------------

#[cfg(windows)]
mod sys {
    //! DPAPI, in a file whose DACL is this store's real access control.
    //!
    //! # Two mechanisms, and which one is doing the work
    //!
    //! `CryptProtectData` with `CRYPTPROTECT_LOCAL_MACHINE` produces a blob
    //! that **any process on this machine** can unprotect. That is not a
    //! weakness in the flag, it is the definition of machine scope, and it is
    //! what D13 needs: a service starting at boot, under an account that has
    //! never logged in, has no user master key to decrypt with. The
    //! consequence is that the encryption is not the access control — the
    //! file's DACL is. `07-security.md` says the same thing from the other
    //! end: *"Stored only in the machine-scoped secret store, ACL'd to the
    //! service account."*
    //!
    //! The user-scoped store passes no scope flag, so the blob is bound to the
    //! calling account's master key. There the encryption *is* an access
    //! control, and the DACL is a second one.
    //!
    //! # The DACL, and why it is not `process.rs`'s
    //!
    //! [`crate::process::RestrictiveHandoff`] writes
    //! `D:P(A;;FA;;;BA)(A;;FA;;;<this account>)` and documents at length why it
    //! carries no `SY` ACE: that file's writer and reader are the same
    //! process, so if the process is `LocalSystem` its own SID *is* S-1-5-18
    //! and a separate ACE adds nothing.
    //!
    //! This store's writer and reader are **not** the same process. `auth
    //! login` runs as the interactive operator; the daemon runs as whatever
    //! `service install` registered, which defaults to `LocalSystem`. So `SY`
    //! is load-bearing here in exactly the case where it was redundant there,
    //! and the machine-scoped DACL carries it. The user-scoped DACL does not,
    //! because a user-scoped store is deliberately not for a service.
    //!
    //! The third trustee is `OW` — OWNER RIGHTS, S-1-3-4 — rather than the
    //! creating account's SID read back out of the process token. When a DACL
    //! contains an ACE for OWNER RIGHTS, that ACE is what the object's owner
    //! gets, and the owner of a file is the account that created it. So `OW`
    //! says "the account that ran `auth login` keeps access to what it stored"
    //! without opening a process token, without a `TOKEN_USER` buffer, and
    //! without a second copy of the SID lookup `process.rs` already carries.
    //!
    //! **That sentence held only while `auth login` was the sole writer.** Token
    //! renewal made the daemon a second writer under a different account, and
    //! because every write creates a new file, the owner moved with it and `OW`
    //! stopped meaning the operator. [`replacement_sddl`] is what keeps the
    //! grant `OW` describes from evaporating; it carries the previous owner's
    //! SID onto the replacement explicitly.
    //!
    //! # One store per host, and what a second operator actually gets
    //!
    //! An earlier version of this paragraph said that ownership moves with the
    //! write, so a second non-administrative operator's `auth login` "takes"
    //! the store. **That was wrong, and it was wrong in the optimistic
    //! direction.** Ownership does not move, because the write never lands:
    //! `store` finishes with a replacing rename, a replacing rename deletes the
    //! target, and delete is granted by `DELETE` on the file or
    //! `FILE_DELETE_CHILD` on its parent. `sddl(Machine)` names `SY`, `BA` and
    //! `OW`, none of which is operator B; and a stock `%ProgramData%` grants
    //! `BUILTIN\Users` only `(OI)(CI)(RX)` plus `(CI)(WD,AD,WEA,WA)` — `WD`
    //! lets B create the temporary, and the absence of `DC` and `DE` is what
    //! denies the rename. So B's `auth login` **fails**.
    //!
    //! That is the correct behaviour, and it is the behaviour this store now
    //! states rather than stumbles into. **The machine-scoped value is the
    //! host's one credential, not an operator's.** `07-security.md` counts the
    //! persisted credential surface and gets to one; `service install`
    //! registers one service reading one store; the domain has one `Host` and
    //! `d1`'s lock permits one agent. A second operator does not get a second
    //! store, and whether B may overwrite A's token is a policy question whose
    //! answer is "only if B is trusted with this host" — which on Windows is
    //! spelled *administrator*, and `BA` already grants it.
    //!
    //! What changed is the *failure*, not the policy. [`cannot_replace`] asks
    //! before anything is encrypted or written, so B gets a message naming the
    //! three ways forward instead of a bare "Access is denied" raised at the
    //! last step of the write, after a valid machine-decryptable blob of a live
    //! token has already been placed on disk.
    //!
    //! Widening the DACL was considered and rejected. The DACL is the **entire**
    //! access control here — a machine-scope DPAPI blob is unprotectable by any
    //! process on the host, by definition — so an ACE that let B replace the
    //! file would also let every interactive account on the machine read the
    //! one credential the product holds. The reader that actually matters is
    //! the service account, which `SY` covers by default and which `d3` grants
    //! explicitly when `service install` registers a least-privilege account
    //! instead (`05-infrastructure.md`, service behaviour, item 2).
    //!
    //! [`crate::process::permissions_summary`] reads the result back, and it
    //! treats an *unprotected* DACL as broadly readable because an inherited
    //! one is not this program's to vouch for. That is why every DACL below
    //! begins `D:P`, and why the file carries its own rather than inheriting
    //! `%ProgramData%`'s, which grants `BU` read.
    //!
    //! # Write, then replace
    //!
    //! The blob goes to a temporary file *carrying its final DACL from the
    //! moment it exists*, is `sync_all`ed, and is then renamed over the target.
    //! `process.rs` argues the first half — a file created and then tightened
    //! is readable for however long the gap lasts. The second half is this
    //! store's own: the value is long-lived, so a write interrupted half way
    //! must not leave a truncated blob where a whole one was.

    use std::fs::File;
    use std::io::{self, Write as _};
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::FromRawHandle;
    use std::path::{Path, PathBuf};

    use windows::Win32::Foundation::{ERROR_SUCCESS, HLOCAL, LocalFree};
    use windows::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        GetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT,
    };
    use windows::Win32::Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_LOCAL_MACHINE, CRYPTPROTECT_UI_FORBIDDEN,
        CryptProtectData, CryptUnprotectData,
    };
    use windows::Win32::Security::{
        OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES,
    };
    use windows::Win32::Storage::FileSystem::{
        CREATE_NEW, CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
        FILE_SHARE_NONE,
    };
    use windows::core::{PCWSTR, PWSTR};

    use super::{
        APPLICATION, DIRECTORY, ITEM, ORGANIZATION, QUALIFIER, SecretScope, TEMP_PREFIX, overwrite,
        sweep_temporaries,
    };

    /// Optional entropy mixed into every blob.
    ///
    /// **Not a secret**, and nothing here pretends otherwise: it is a constant
    /// in a published binary. It binds a blob to this product, so that a
    /// machine-scoped blob found on disk is not readable by a passing program
    /// that merely calls `CryptUnprotectData` with no arguments, and so that a
    /// value written by some future second store cannot be silently read back
    /// by this one. Against an attacker holding the binary it buys nothing.
    const ENTROPY: &[u8] = b"io.github.IvanMurzak.runner-manager/user-access-token/v1";

    /// The file the blob lives in.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(super) struct Site {
        file: PathBuf,
    }

    pub(super) fn standard_site(scope: SecretScope) -> Result<Site, String> {
        let root = match scope {
            // `%ProgramData%` rather than `%LOCALAPPDATA%`, because the whole
            // requirement is that an account which has never logged in can
            // read it — and `%LOCALAPPDATA%` does not exist for such an
            // account until its profile is loaded.
            SecretScope::Machine => std::env::var_os("ProgramData")
                .map(PathBuf::from)
                .ok_or_else(|| {
                    "this Windows reports no %ProgramData%, so the machine-wide \
                     application-data directory cannot be resolved. Set ProgramData, or \
                     install the service with --start-at login to use the user-scoped store."
                        .to_string()
                })?
                .join(ORGANIZATION)
                .join(APPLICATION),
            SecretScope::User => {
                directories::ProjectDirs::from(QUALIFIER, ORGANIZATION, APPLICATION)
                    .ok_or_else(|| {
                        "the operating system reports no home directory for this account, so \
                         the user-scoped store cannot be resolved. A service account \
                         configured with no profile normally hits this; give the account a \
                         home directory, or use the machine-scoped store."
                            .to_string()
                    })?
                    .data_local_dir()
                    .to_path_buf()
            }
        };
        Ok(Site {
            file: root.join(DIRECTORY).join(format!("{ITEM}.dpapi")),
        })
    }

    pub(super) fn rooted_site(scope: SecretScope, root: &Path) -> Result<Site, String> {
        // The scope is a path segment here and is not one under a standard
        // site, because a standard site gets its separation from the root:
        // `%ProgramData%` against `%LOCALAPPDATA%`. Under one caller-named root
        // there is no such separation, and two stores sharing a file is the
        // failure `the_two_variants_do_not_share_a_value` exists to catch --
        // `auth logout` under one scope would silently purge the other.
        Ok(Site {
            file: root
                .join(DIRECTORY)
                .join(scope.as_str())
                .join(format!("{ITEM}.dpapi")),
        })
    }

    pub(super) fn describe(site: &Site) -> String {
        format!("DPAPI blob at {}", site.file.display())
    }

    pub(super) fn guard(site: &Site) -> PathBuf {
        site.file.clone()
    }

    /// The protected DACL a store of this scope gets, in SDDL.
    ///
    /// Split out and `pub(super)` so a test can assert the exact string rather
    /// than infer it from a file, and so a reviewer can read the two DACLs
    /// side by side.
    pub(super) const fn sddl(scope: SecretScope) -> &'static str {
        match scope {
            SecretScope::Machine => "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)",
            SecretScope::User => "D:P(A;;FA;;;BA)(A;;FA;;;OW)",
        }
    }

    /// The DACL a *replacement* gets: [`sddl`], plus the account that owned
    /// what is being replaced.
    ///
    /// # Why `OW` alone stopped being enough
    ///
    /// `OW` is OWNER RIGHTS, and the owner of a file is whoever created it.
    /// That made `OW` an exact statement of *"the account that ran `auth login`
    /// keeps access to what it stored"* for as long as `auth login` was the
    /// only writer.
    ///
    /// Token renewal made the daemon a second writer with a different
    /// identity. [`store`] finishes by renaming a temporary over the target, so
    /// every write creates a new file, and the new file's owner is whoever
    /// created it — `LocalSystem` for a daemon installed at boot. `OW` then
    /// resolves to `LocalSystem`, the operator matches none of the three ACEs,
    /// and an unelevated `auth status` cannot read the store or even its ACL.
    ///
    /// Observed on 2026-08-29: a store readable at `07:50Z` and unreadable at
    /// `07:58Z`, with nothing between the two but the daemon renewing its
    /// eight-hour token. See `docs/spikes/token-expiry-and-renewal.md`.
    ///
    /// # Why the previous owner, rather than preserving ownership
    ///
    /// Setting a new file's owner to an account that is not the caller's needs
    /// `SE_RESTORE_NAME`, which `LocalSystem` holds but a least-privilege
    /// service account — which `service install` can register — does not. An
    /// ACE needs nothing: the writer created the file and so may say who else
    /// reaches it. This works the same for both, which is why it is the
    /// mechanism rather than the fallback.
    ///
    /// This widens nothing. The previous owner already had full control
    /// through `OW`; carrying the SID forward is what keeps a grant that
    /// already existed from evaporating when somebody else writes.
    ///
    /// # Why the previous *grants* and not just the previous owner
    ///
    /// Carrying the owner alone survives exactly one write and then undoes
    /// itself. After the first renewal the owner is the daemon and the operator
    /// is named by an ACE; at the second renewal the owner read back is the
    /// *daemon's*, so a DACL rebuilt from the owner drops the operator and
    /// locks them out again — the same failure, deferred by eight hours. What
    /// is carried is therefore every SID the previous DACL granted, which
    /// includes the ACE the previous write added.
    ///
    /// [`carried_grants`] reads that set and drops the SIDs the constant
    /// already covers, so the DACL cannot grow by one ACE per write.
    pub(super) fn replacement_sddl(scope: SecretScope, carried: &[String]) -> String {
        let mut text = sddl(scope).to_owned();
        for sid in carried {
            // The SID goes in where a two-letter alias usually does; SDDL takes
            // either.
            text.push_str("(A;;FA;;;");
            text.push_str(sid);
            text.push(')');
        }
        text
    }

    /// Trustees the constant DACL already grants, in both spellings.
    ///
    /// The aliases are what [`sddl`] itself writes, so re-emitting them would
    /// double every ACE in the base. The two SIDs are the same accounts as
    /// `SY` and `BA`, which is the spelling [`previous_owner`] hands back:
    /// `ConvertSidToStringSidW` always answers `S-1-…`, never an alias.
    const ALREADY_GRANTED: [&str; 5] = ["SY", "BA", "OW", "S-1-5-18", "S-1-5-32-544"];

    /// Every account the value being replaced was readable by, so that
    /// replacing it does not quietly take the store away from one of them.
    ///
    /// The owner, because `OW` granted it; plus the SIDs already named
    /// explicitly, because those are the owners of earlier writes that this
    /// mechanism already rescued. Bounded by [`ALREADY_GRANTED`] and by
    /// deduplication: in practice the set is the one operator who signed in.
    ///
    /// Deliberately infallible, for the reason [`previous_owner`] gives.
    fn carried_grants(path: &Path) -> Vec<String> {
        // The reader `protection` already goes through, rather than a second
        // descriptor round trip of this module's own.
        let dacl = crate::process::permissions_summary(path)
            .map(|summary| summary.description)
            .unwrap_or_default();
        merge_grants(previous_owner(path).as_deref(), &dacl)
    }

    /// [`carried_grants`] without the two reads, which is where its one rule
    /// lives and the only part a test can drive.
    ///
    /// A test process is one account: it cannot become `LocalSystem`, so it
    /// cannot make the owner move between writes, so driving [`store`] can
    /// never reach the case this rule exists for. Passing the owner and the
    /// DACL in is what makes "the writer is not the previous owner" reachable
    /// at all.
    pub(super) fn merge_grants(previous_owner: Option<&str>, previous_dacl: &str) -> Vec<String> {
        let mut carried: Vec<String> = Vec::new();
        let mut add = |sid: &str| {
            if !ALREADY_GRANTED.contains(&sid) && !carried.iter().any(|seen| seen == sid) {
                carried.push(sid.to_owned());
            }
        };
        if let Some(owner) = previous_owner {
            add(owner);
        }
        for trustee in trustees(previous_dacl) {
            add(&trustee);
        }
        carried
    }

    /// Every trustee an SDDL DACL names, in whatever spelling it names them.
    ///
    /// An ACE is `(type;flags;rights;object;inherit;trustee)`, so the trustee is
    /// what follows the last `;` before the closing parenthesis.
    ///
    /// # Why not "the ones written as `S-1-…`"
    ///
    /// Because Windows does not read back what was written. A DACL built with
    /// `S-1-5-21-…-500` comes out of
    /// `ConvertSecurityDescriptorToStringSecurityDescriptorW` as `(A;;FA;;;LA)`
    /// — the alias for the built-in Administrator — and any other well-known
    /// account behaves the same way. Filtering on the `S-1-` prefix therefore
    /// dropped exactly the accounts whose grant had already been rescued once,
    /// so the carry survived one write and undid itself on the next, which is
    /// the bug it exists to prevent.
    ///
    /// Found by CI, whose Windows runner signs in as that account. It passes on
    /// an ordinary developer machine, where the operator has a plain
    /// `S-1-5-21-…-1001` that survives the round trip unchanged.
    ///
    /// [`ALREADY_GRANTED`] is what keeps the base DACL's own aliases out.
    pub(super) fn trustees(sddl: &str) -> Vec<String> {
        let mut found = Vec::new();
        for ace in sddl.split('(').skip(1) {
            let Some(body) = ace.split(')').next() else {
                continue;
            };
            let Some(trustee) = body.rsplit(';').next() else {
                continue;
            };
            if !trustee.is_empty() && !found.iter().any(|seen| seen == trustee) {
                found.push(trustee.to_owned());
            }
        }
        found
    }

    /// The SID of the account that owns the file already there, as a string.
    ///
    /// `None` when there is no file, when its owner cannot be read, or when the
    /// SID will not convert — all of which mean the same thing to the caller:
    /// there is no previous grant to carry forward, so write [`sddl`] as it
    /// stands. A first write reaches this with nothing on disk and takes that
    /// path.
    ///
    /// Deliberately infallible. A store that refused to write because it could
    /// not read a security descriptor would trade a working credential for a
    /// tidier ACL.
    fn previous_owner(path: &Path) -> Option<String> {
        let wide = to_wide(path);
        let mut owner = PSID::default();
        let mut descriptor = PSECURITY_DESCRIPTOR(std::ptr::null_mut());
        // SAFETY: `wide` is NUL-terminated and outlives the call. `descriptor`
        // receives a LocalAlloc'd descriptor freed below on every path, and
        // `owner` points into it rather than owning anything itself.
        let status = unsafe {
            GetNamedSecurityInfoW(
                PCWSTR(wide.as_ptr()),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION,
                Some(&mut owner),
                None,
                None,
                None,
                &mut descriptor,
            )
        };
        if status != ERROR_SUCCESS {
            return None;
        }

        let mut sid_string = PWSTR::null();
        // SAFETY: `owner` points into the descriptor, which is still live.
        let converted = unsafe { ConvertSidToStringSidW(owner, &mut sid_string) };
        let text = match converted {
            // SAFETY: the conversion succeeded, so `sid_string` is a
            // LocalAlloc'd NUL-terminated string, freed immediately after.
            Ok(()) => {
                let text = unsafe { sid_string.to_string() }.ok();
                unsafe {
                    let _ = LocalFree(Some(HLOCAL(sid_string.0.cast())));
                }
                text
            }
            Err(_) => None,
        };
        // SAFETY: LocalAlloc'd by `GetNamedSecurityInfoW`, freed exactly once.
        unsafe {
            let _ = LocalFree(Some(HLOCAL(descriptor.0)));
        }
        text
    }

    /// The access right a replacing rename needs on the file it replaces.
    ///
    /// `MOVEFILE_REPLACE_EXISTING` deletes the target, and delete is granted by
    /// `DELETE` on the object or by `FILE_DELETE_CHILD` on its parent. Probing
    /// for it is `CreateFileW` with `dwDesiredAccess = DELETE`, which
    /// [`std::os::windows::fs::OpenOptionsExt::access_mode`] reaches without
    /// another FFI declaration.
    const DELETE: u32 = 0x0001_0000;

    /// Whether this account may replace the value already in the store, and if
    /// not, why an operator is seeing it.
    ///
    /// Returns `None` when there is nothing there, or when the existing value
    /// can be replaced — the ordinary cases.
    ///
    /// # What this catches
    ///
    /// A second non-administrative operator on a shared host. Their `auth
    /// login` inherits `WD` (create file) from `%ProgramData%` so the temporary
    /// file is written happily, and then the rename over the first operator's
    /// file is denied, because `sddl(Machine)` names `SY`, `BA` and `OW` and
    /// this account is none of the three. Left to the rename, that surfaces as
    /// a bare "Access is denied" at the last step of the write, after a valid
    /// machine-decryptable blob of a real token has already been put on disk.
    ///
    /// # Why it refuses rather than widening the DACL
    ///
    /// **This product keeps one machine-scoped credential per host, and that is
    /// the intended model rather than an accident of the ACL.**
    /// `07-security.md` counts the persisted credential surface and gets to
    /// one; `05-infrastructure.md` has `service install` register one service
    /// reading one store; the domain has one `Host`, and `d1`'s single-instance
    /// lock allows one agent. The value is *the host's* credential, not an
    /// operator's — so a second operator does not get a second store, and the
    /// question "may B overwrite A's token" is a policy question with a policy
    /// answer: only if B is trusted with the host, which on Windows means
    /// administrator.
    ///
    /// Widening the DACL to make the rename succeed would give every
    /// interactive account on the machine write access to the one credential
    /// the product holds, and read access with it, since the DACL is the
    /// **entire** access control here — a machine-scope DPAPI blob is
    /// unprotectable by any process on the host by definition. That trade is
    /// not worth a smoother second login.
    fn cannot_replace(site: &Site) -> Option<io::Error> {
        use std::os::windows::fs::OpenOptionsExt as _;

        match std::fs::OpenOptions::new()
            .access_mode(DELETE)
            .open(&site.file)
        {
            // Replaceable, or nothing there to replace.
            Ok(_) => None,
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => Some(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "the machine-scoped store at {} already holds a token that belongs to \
                     another account on this host, and this account may not replace it. This \
                     product keeps one machine-scoped credential per host -- it is the host's \
                     credential, not an operator's -- so a second operator does not get a \
                     second store. Either run `auth logout` as the account that stored it, or \
                     run `auth login` from an elevated prompt, since the local Administrators \
                     group is granted access, or install the service with `--start-at login`, \
                     which uses the per-user store instead. Nothing was written.",
                    site.file.display()
                ),
            )),
            // Anything else is not this condition. Say nothing and let the
            // write report whatever it actually runs into, rather than
            // inventing a diagnosis from an unrelated errno.
            Err(_) => None,
        }
    }

    pub(super) fn store(site: &Site, scope: SecretScope, plaintext: &[u8]) -> io::Result<()> {
        let directory = site
            .file
            .parent()
            .ok_or_else(|| io::Error::other("the store path has no parent directory"))?;
        std::fs::create_dir_all(directory)?;

        // Before anything is encrypted or written. The point of asking here is
        // that the alternative -- finding out at the rename -- means a valid,
        // machine-decryptable blob of a live token has already been placed on
        // disk before the refusal.
        if let Some(refusal) = cannot_replace(site) {
            return Err(refusal);
        }

        let blob = protect(plaintext, scope)?;

        // Read before the temporary exists, from the file about to be replaced.
        // A renewal writes as the daemon's account and would otherwise take
        // `OW` away from the operator who signed in; see `replacement_sddl`.
        let descriptor = replacement_sddl(scope, &carried_grants(&site.file));

        let temporary = directory.join(format!("{TEMP_PREFIX}{}.tmp", uuid::Uuid::new_v4()));
        let written = (|| -> io::Result<()> {
            let mut file = create_protected_file(&temporary, &descriptor)?;
            file.write_all(&blob)?;
            file.flush()?;
            file.sync_all()
        })();
        if let Err(error) = written {
            return Err(discard(&temporary, error));
        }

        // `std::fs::rename` is `MoveFileExW(.., MOVEFILE_REPLACE_EXISTING)` on
        // Windows, so this replaces a previous token rather than failing. The
        // file keeps its own security descriptor across the move, so the DACL
        // applied at creation is the one the store ends up with.
        if let Err(error) = std::fs::rename(&temporary, &site.file) {
            // The probe above should have caught the second-operator case, but
            // it is a probe and this is a race: another account can take the
            // file between the two calls. Report the same diagnosis rather than
            // the bare denial, then discard the blob either way.
            let error = if error.kind() == io::ErrorKind::PermissionDenied {
                cannot_replace(site).unwrap_or(error)
            } else {
                error
            };
            return Err(discard(&temporary, error));
        }
        Ok(())
    }

    /// Scrubs and removes a temporary that will not become the store, and folds
    /// a failure to do so into the error the caller is already returning.
    ///
    /// A temporary that survives a failed `store` is a valid machine-scope
    /// DPAPI blob of a real token, sitting under a name nobody looks at.
    /// Removing it was already the behaviour; what was missing is that the
    /// removal was `let _ =`, so a temporary that could *not* be removed left
    /// the token on disk with nothing said about it.
    ///
    /// A blanket [`sweep_temporaries`] is deliberately not used here. Its own
    /// documentation says why: two `store` calls can be in flight at once, and
    /// sweeping the directory would remove the other one's live temporary. This
    /// removes exactly the file this call created.
    fn discard(temporary: &Path, error: io::Error) -> io::Error {
        let _ = overwrite(temporary);
        match std::fs::remove_file(temporary) {
            Ok(()) => error,
            Err(removal) if removal.kind() == io::ErrorKind::NotFound => error,
            Err(removal) => io::Error::new(
                error.kind(),
                format!(
                    "{error}. A temporary file holding the encrypted token was also left at \
                     {} and could not be removed ({removal}); delete it by hand.",
                    temporary.display()
                ),
            ),
        }
    }

    /// Why an operator cannot read a store that is theirs, and the one command
    /// that gives it back.
    ///
    /// # The state this diagnoses
    ///
    /// A file that exists and that this account may not read. On this store
    /// that has one cause: the DACL grants `SY`, `BA` and `OW`, and the owner
    /// is whoever wrote last. A daemon under `LocalSystem` renewing the token
    /// became that owner, so `OW` stopped meaning the operator.
    ///
    /// # Why a message and not a repair
    ///
    /// Later versions carry the previous owner onto every replacement, so this
    /// cannot start. It does not *end* on a host where it already happened:
    /// the file on disk grants nobody but the service, and there is nothing in
    /// its DACL left to carry, so every renewal reproduces the same DACL and
    /// the operator is locked out for good. Taking ownership back is what
    /// seeds the grant that then propagates by itself.
    ///
    /// The product will not do that silently. Ownership of the file holding
    /// this host's credential is not something a status command should change
    /// under an operator, and the account that must run it is an
    /// administrator, which this process may not be. So it says exactly what to
    /// run.
    ///
    /// Watched on 2026-08-30: `auth status` unreadable at every attempt,
    /// `takeown` on the guard, and `Credential: authenticated` from an
    /// unelevated prompt immediately after.
    fn locked_out(site: &Site, source: &io::Error) -> io::Error {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{source}. The file exists but this account may not read it, which on this \
                 store means its owner changed: the service renews the token under its own \
                 account, and the credential is granted to whoever owns the file. Take \
                 ownership back from an elevated prompt and the access returns immediately, \
                 and stays -- every later renewal carries the grant forward:\n    takeown /f \
                 \"{}\"\nAn `auth logout` followed by `auth login`, also elevated, is the \
                 heavier alternative and costs a fresh sign-in.",
                site.file.display()
            ),
        )
    }

    pub(super) fn load(site: &Site, _scope: SecretScope) -> io::Result<Option<Vec<u8>>> {
        let blob = match std::fs::read(&site.file) {
            Ok(blob) => blob,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            // Asked before the bare denial is returned, for the same reason
            // `cannot_replace` exists on the write path: `Access is denied` on
            // a file the operator owns the machine of is a true statement that
            // helps nobody.
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                return Err(locked_out(site, &error));
            }
            Err(error) => return Err(error),
        };
        if blob.is_empty() {
            // An empty file is the remnant of an interrupted write, not a
            // value. Reported as `InvalidData` so the caller says `Corrupt`
            // rather than starting a fresh login over the top of it.
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the stored file is empty",
            ));
        }
        unprotect(&blob).map(Some)
    }

    pub(super) fn delete(site: &Site) -> io::Result<bool> {
        // Zeroed before it is unlinked, the same as the Linux backend. The
        // value here is a DPAPI blob rather than plaintext, so the fill buys
        // less; it costs one `write`, and it keeps one mechanism instead of two
        // on the path the Definition of Done calls "leaves no recoverable
        // remnant". `overwrite`'s documentation carries the disclaimer.
        let _ = overwrite(&site.file);

        let removed = match std::fs::remove_file(&site.file) {
            Ok(()) => true,
            Err(error) if error.kind() == io::ErrorKind::NotFound => false,
            Err(error) => return Err(error),
        };
        if let Some(directory) = site.file.parent() {
            sweep_temporaries(directory);
        }
        Ok(removed)
    }

    // -- DPAPI ---------------------------------------------------------------

    /// Turns a windows-rs error into one whose [`io::Error::kind`] means
    /// something.
    ///
    /// `Error::code()` is an **HRESULT**, and handing that straight to
    /// `from_raw_os_error` is what an earlier version did. It produces an
    /// `io::Error` whose `raw_os_error` is `0x8007_0005` rather than `5`, so
    /// `kind()` is `Uncategorized` and a caller cannot tell "access denied"
    /// from anything else — which matters here, because the second operator
    /// case below is precisely an access denial a caller has to recognise.
    ///
    /// The `0x8007_xxxx` range is `HRESULT_FROM_WIN32`, so its low sixteen bits
    /// are the Win32 code and unwrapping them restores the classification.
    /// Anything outside that range is not a Win32 error and is passed through
    /// as it is.
    pub(super) fn io_error(error: &windows::core::Error) -> io::Error {
        let code = error.code().0;
        if (code as u32) & 0xffff_0000 == 0x8007_0000 {
            io::Error::from_raw_os_error(code & 0xffff)
        } else {
            io::Error::from_raw_os_error(code)
        }
    }

    /// A blob descriptor over a buffer the caller keeps alive.
    fn blob_of(bytes: &mut [u8]) -> CRYPT_INTEGER_BLOB {
        CRYPT_INTEGER_BLOB {
            cbData: u32::try_from(bytes.len()).unwrap_or(u32::MAX),
            pbData: bytes.as_mut_ptr(),
        }
    }

    /// Copies `len` bytes out of `ptr` and zeroes the source.
    ///
    /// Split out from [`take_blob`] for one reason: a scrub that happens inside
    /// an `unsafe` block around a DPAPI buffer can be asserted by nothing —
    /// once `LocalFree` has run there is nothing left to look at. Given a
    /// pointer, the scrub is a property a test can check against a buffer Rust
    /// owns, which is what
    /// [`tests::windows::the_dpapi_buffer_is_scrubbed_before_it_is_freed`]
    /// does.
    ///
    /// # Safety
    ///
    /// `ptr` must be valid for reads *and writes* of `len` bytes, and must not
    /// be aliased for the duration of the call.
    pub(super) unsafe fn copy_and_scrub(ptr: *mut u8, len: usize) -> Vec<u8> {
        use secrecy::zeroize::Zeroize as _;

        // SAFETY: the caller guarantees `ptr` is valid for `len` bytes and
        // unaliased, so one exclusive slice over it is sound.
        let source = unsafe { std::slice::from_raw_parts_mut(ptr, len) };
        let copy = source.to_vec();
        source.zeroize();
        copy
    }

    /// Copies a DPAPI-allocated output blob into a `Vec`, scrubs the original,
    /// and frees it.
    ///
    /// The scrub is not optional and is not only for tidiness. On the
    /// [`unprotect`] path this buffer holds **the user access token in
    /// plaintext**, and `LocalFree` returns it to the process heap exactly as
    /// it is — where a later allocation, a crash dump, or a core file can pick
    /// it up. Every other copy this module makes is scrubbed (`protect`'s
    /// input, `decode`'s rejected bytes); this one was the exception.
    ///
    /// It runs on the [`protect`] path too, where the buffer is ciphertext and
    /// the scrub buys nothing. Making it conditional would buy a branch and an
    /// opportunity to get the condition wrong.
    ///
    /// # Safety
    ///
    /// `out` must be an output blob DPAPI filled in and that has not yet been
    /// freed.
    unsafe fn take_blob(out: &mut CRYPT_INTEGER_BLOB) -> Vec<u8> {
        if out.pbData.is_null() {
            return Vec::new();
        }
        // SAFETY: DPAPI filled this blob in, so the pointer is valid for
        // `cbData` bytes and nothing else holds a reference to it.
        let bytes = unsafe { copy_and_scrub(out.pbData, out.cbData as usize) };
        // SAFETY: the buffer was `LocalAlloc`ed by DPAPI and is freed once.
        unsafe {
            let _ = LocalFree(Some(HLOCAL(out.pbData.cast())));
        }
        out.pbData = std::ptr::null_mut();
        out.cbData = 0;
        bytes
    }

    fn protect(plaintext: &[u8], scope: SecretScope) -> io::Result<Vec<u8>> {
        use secrecy::zeroize::Zeroize as _;

        let mut input = plaintext.to_vec();
        let mut entropy = ENTROPY.to_vec();
        let input_blob = blob_of(&mut input);
        let entropy_blob = blob_of(&mut entropy);
        let mut out = CRYPT_INTEGER_BLOB::default();

        // `CRYPTPROTECT_UI_FORBIDDEN` on both scopes, without exception. A
        // daemon that starts at boot has no desktop to draw a prompt on, and a
        // call blocked waiting for one is indistinguishable from a hang.
        let flags = CRYPTPROTECT_UI_FORBIDDEN
            | match scope {
                SecretScope::Machine => CRYPTPROTECT_LOCAL_MACHINE,
                SecretScope::User => 0,
            };

        // SAFETY: both input descriptors point into `input` and `entropy`,
        // which outlive the call; `out` is a zeroed descriptor DPAPI fills in
        // and `take_blob` frees exactly once.
        let result = unsafe {
            CryptProtectData(
                &raw const input_blob,
                PCWSTR::null(),
                Some(&raw const entropy_blob),
                None,
                None,
                flags,
                &raw mut out,
            )
        };

        // The plaintext copy this function made is scrubbed on every path out,
        // the failure path included.
        input.zeroize();

        result.map_err(|error| io_error(&error))?;
        // SAFETY: `CryptProtectData` returned success, so `out` is a blob it
        // allocated and has not freed.
        Ok(unsafe { take_blob(&mut out) })
    }

    fn unprotect(blob: &[u8]) -> io::Result<Vec<u8>> {
        let mut input = blob.to_vec();
        let mut entropy = ENTROPY.to_vec();
        let input_blob = blob_of(&mut input);
        let entropy_blob = blob_of(&mut entropy);
        let mut out = CRYPT_INTEGER_BLOB::default();

        // SAFETY: as `protect`.
        let result = unsafe {
            CryptUnprotectData(
                &raw const input_blob,
                None,
                Some(&raw const entropy_blob),
                None,
                None,
                CRYPTPROTECT_UI_FORBIDDEN,
                &raw mut out,
            )
        };

        match result {
            // SAFETY: success, so `out` is DPAPI's and unfreed.
            Ok(()) => Ok(unsafe { take_blob(&mut out) }),
            // Every way this fails means one thing to a caller: there are bytes
            // here and they are not a value this store can read back. Reported
            // as `InvalidData` so it surfaces as `Corrupt` and sends the
            // operator to `auth logout`, rather than as a transient read
            // failure that something would retry forever.
            Err(error) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "the stored bytes could not be unprotected with this machine's DPAPI key \
                     ({error})"
                ),
            )),
        }
    }

    // -- The protected file --------------------------------------------------

    fn to_wide(path: &Path) -> Vec<u16> {
        path.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    /// Creates a new file carrying `descriptor` from the moment it exists.
    ///
    /// Takes the SDDL rather than the scope because a replacement's DACL is
    /// [`sddl`] plus the previous owner — see [`replacement_sddl`] — and a file
    /// that is created and then widened is unreadable to the account it is
    /// being widened for for however long the gap lasts.
    fn create_protected_file(path: &Path, descriptor: &str) -> io::Result<File> {
        let sddl_wide: Vec<u16> = descriptor
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let mut descriptor = PSECURITY_DESCRIPTOR(std::ptr::null_mut());
        // SAFETY: `sddl_wide` is a NUL-terminated UTF-16 buffer that outlives
        // the call, and `descriptor` receives a LocalAlloc'd descriptor freed
        // below on both paths.
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(sddl_wide.as_ptr()),
                SDDL_REVISION_1,
                &mut descriptor,
                None,
            )
        }
        .map_err(|error| io_error(&error))?;

        let attributes = SECURITY_ATTRIBUTES {
            nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(u32::MAX),
            lpSecurityDescriptor: descriptor.0,
            // False: no child process this agent spawns has any business
            // inheriting a handle to the token.
            bInheritHandle: windows::core::BOOL(0),
        };

        let wide = to_wide(path);
        // SAFETY: `wide` is NUL-terminated and outlives the call; `attributes`
        // points at a descriptor that is still live here.
        let handle = unsafe {
            CreateFileW(
                PCWSTR(wide.as_ptr()),
                FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0,
                FILE_SHARE_NONE,
                Some(&raw const attributes),
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )
        };

        // SAFETY: the descriptor was LocalAlloc'd by the conversion above and
        // is freed exactly once, after the last use of `attributes`.
        unsafe {
            let _ = LocalFree(Some(HLOCAL(descriptor.0)));
        }

        let handle = handle.map_err(|error| io_error(&error))?;
        // SAFETY: `CreateFileW` returned success, so the handle is a valid
        // owned file handle this `File` takes over.
        Ok(unsafe { File::from_raw_handle(handle.0) })
    }
}

// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
mod sys {
    //! A generic-password item in a keychain, and which keychain is the whole
    //! of the scope.
    //!
    //! | scope | keychain | why |
    //! |---|---|---|
    //! | [`SecretScope::Machine`] | `/Library/Keychains/System.keychain` | the only keychain a process with no login session can open. A LaunchAgent starts at login; a LaunchDaemon starts at boot and has no user keychain to reach for. |
    //! | [`SecretScope::User`] | `~/Library/Keychains/login.keychain-db` | the operator's own keychain, unlocked by their login, gone when they log out. |
    //!
    //! # Why the login keychain is opened by path
    //!
    //! `SecKeychainCopyDefault` would give the account's *current* default
    //! keychain, which is more nearly what an operator expects. It hands back a
    //! handle and no path — and this store has to be able to name the file
    //! whose mode protects the value, both for `host show` and for
    //! [`super::SecretStore::protection`]. A store that could not say what
    //! protects it would be asserting the security property by assumption.
    //! So the login keychain is resolved by path, `login.keychain-db` first and
    //! the pre-Sierra `login.keychain` second, and an operator who has moved
    //! their default elsewhere gets the store in their login keychain rather
    //! than wherever the default now points.
    //!
    //! # User interaction is disabled around every call
    //!
    //! `SecKeychainSetUserInteractionAllowed(false)` for the duration of each
    //! operation, unconditionally. A daemon started at boot has no desktop, and
    //! a keychain call that decides to draw an unlock panel there does not fail
    //! — it waits. `errSecInteractionNotAllowed` returned in a second is a
    //! diagnosable condition; a process wedged behind an invisible dialog is
    //! not.
    //!
    //! # What a rooted keychain is for
    //!
    //! [`super::PlatformSecretStore::rooted_at`] creates a keychain of its own
    //! under the caller's root. That is the only way the suite can exercise
    //! this backend at all: writing to `/Library/Keychains/System.keychain`
    //! needs `root`, and writing to the login keychain would destroy a
    //! developer's real `auth login` every time the tests ran. What it covers
    //! and what it does not is set out on `rooted_at` itself.

    use std::io;
    use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
    use std::path::{Path, PathBuf};

    use security_framework::os::macos::keychain::{CreateOptions, KeychainSettings, SecKeychain};

    use super::{DIRECTORY, ITEM, KEYCHAIN_SERVICE, ROOTED_KEYCHAIN_PASSWORD, SecretScope};

    /// The composed product identity, as a plain `&str`.
    ///
    /// [`KEYCHAIN_SERVICE`] is a `LazyLock<String>` so that it is built from
    /// `crate::paths`'s three segments rather than written out a second time.
    /// This is the one place that unwraps it, so the call sites below read as
    /// they did when it was a constant.
    pub(super) fn service() -> &'static str {
        &KEYCHAIN_SERVICE
    }

    /// `errSecItemNotFound`. Hard-coded rather than imported because
    /// `security-framework-sys` is not a dependency of this workspace and
    /// adding one would be an A-group change for a single integer.
    const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;
    /// `errSecNoSuchKeychain`. What a keychain file that is not there answers
    /// with, which is absence rather than failure.
    const ERR_SEC_NO_SUCH_KEYCHAIN: i32 = -25294;

    /// The System Keychain's master key. Root-only, and the reason an
    /// unprivileged local user cannot read a machine-scoped item even though
    /// the keychain database beside it is world-readable.
    const SYSTEM_KEYCHAIN_MASTER_KEY: &str = "/var/db/SystemKey";
    /// The machine-scoped keychain itself.
    const SYSTEM_KEYCHAIN: &str = "/Library/Keychains/System.keychain";

    /// Which keychain, and where it is.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(super) struct Site {
        path: PathBuf,
        kind: Kind,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Kind {
        /// The System Keychain. Written by `root`, readable by a LaunchDaemon.
        System,
        /// The operator's login keychain.
        Login,
        /// A keychain this program created under a caller-named root.
        Rooted,
    }

    pub(super) fn standard_site(scope: SecretScope) -> Result<Site, String> {
        match scope {
            SecretScope::Machine => Ok(Site {
                path: PathBuf::from(SYSTEM_KEYCHAIN),
                kind: Kind::System,
            }),
            SecretScope::User => {
                let home = directories::BaseDirs::new()
                    .ok_or_else(|| {
                        "the operating system reports no home directory for this account, so \
                         the login keychain cannot be resolved. A service account configured \
                         with no profile normally hits this; use the machine-scoped store, \
                         which is what --start-at boot installs."
                            .to_string()
                    })?
                    .home_dir()
                    .join("Library")
                    .join("Keychains");

                // Sierra renamed the login keychain and kept the old one
                // working, so a machine upgraded across that boundary can have
                // either. Prefer the modern name, fall back to the legacy one
                // only when it is the one that actually exists, and resolve to
                // the modern name when neither does so that a first `auth
                // login` creates the right thing.
                let modern = home.join("login.keychain-db");
                let legacy = home.join("login.keychain");
                let path = if modern.exists() || !legacy.exists() {
                    modern
                } else {
                    legacy
                };
                Ok(Site {
                    path,
                    kind: Kind::Login,
                })
            }
        }
    }

    pub(super) fn rooted_site(scope: SecretScope, root: &Path) -> Result<Site, String> {
        // A keychain per scope, for the reason the Windows and Linux backends
        // give a directory per scope: under one caller-named root the two
        // stores have nothing else keeping them apart, and two stores sharing
        // one item means `auth logout` under either scope purges both.
        Ok(Site {
            path: root
                .join(DIRECTORY)
                .join(scope.as_str())
                .join("runner-manager.keychain-db"),
            kind: Kind::Rooted,
        })
    }

    pub(super) fn describe(site: &Site) -> String {
        let kind = match site.kind {
            Kind::System => "System",
            Kind::Login => "login",
            Kind::Rooted => "rooted",
        };
        format!(
            "{kind} keychain {}, item {}/{ITEM}",
            site.path.display(),
            service()
        )
    }

    pub(super) fn guard(site: &Site) -> PathBuf {
        match site.kind {
            // Not the keychain database. `/Library/Keychains/System.keychain`
            // is world-readable and its contents are encrypted; the mode that
            // decides who can decrypt them belongs to the master key beside it.
            // Reporting the database here would answer a question nobody asked,
            // and answer it wrongly.
            Kind::System => PathBuf::from(SYSTEM_KEYCHAIN_MASTER_KEY),
            Kind::Login | Kind::Rooted => site.path.clone(),
        }
    }

    fn sec_error(error: &security_framework::base::Error) -> io::Error {
        io::Error::other(format!(
            "Security.framework returned {} ({error})",
            error.code()
        ))
    }

    fn is_absence(error: &security_framework::base::Error) -> bool {
        matches!(
            error.code(),
            ERR_SEC_ITEM_NOT_FOUND | ERR_SEC_NO_SUCH_KEYCHAIN
        )
    }

    /// Suppresses keychain UI for as long as the returned guard lives.
    ///
    /// Best effort: a platform that refuses the call is not a reason to fail
    /// the operation, only a reason not to have the guarantee. The guard
    /// re-enables interaction on drop, so this never leaks process-wide state
    /// past the call that took it.
    fn without_user_interaction()
    -> Option<security_framework::os::macos::keychain::KeychainUserInteractionLock> {
        SecKeychain::disable_user_interaction().ok()
    }

    /// Opens the keychain, creating a rooted one if asked and if it is missing.
    ///
    /// `Ok(None)` means "there is no such keychain", which for a read is
    /// absence rather than failure.
    fn open(site: &Site, create_if_missing: bool) -> io::Result<Option<SecKeychain>> {
        match site.kind {
            Kind::System | Kind::Login => {
                if !site.path.exists() {
                    return Ok(None);
                }
                SecKeychain::open(&site.path)
                    .map(Some)
                    .map_err(|error| sec_error(&error))
            }
            Kind::Rooted if site.path.exists() => {
                let mut keychain =
                    SecKeychain::open(&site.path).map_err(|error| sec_error(&error))?;
                keychain
                    .unlock(Some(ROOTED_KEYCHAIN_PASSWORD))
                    .map_err(|error| sec_error(&error))?;
                Ok(Some(keychain))
            }
            Kind::Rooted if create_if_missing => Ok(Some(create_rooted(site)?)),
            Kind::Rooted => Ok(None),
        }
    }

    fn create_rooted(site: &Site) -> io::Result<SecKeychain> {
        let directory = site
            .path
            .parent()
            .ok_or_else(|| io::Error::other("the rooted keychain path has no parent directory"))?;
        // `0700` at `mkdir(2)` time, for the reason `crate::paths` gives: a
        // two-step create-then-chmod leaves a window, and here the window is
        // over the directory whose mode is the only thing protecting a rooted
        // keychain.
        std::fs::DirBuilder::new()
            .mode(0o700)
            .recursive(true)
            .create(directory)?;
        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))?;

        let mut keychain = CreateOptions::new()
            .password(ROOTED_KEYCHAIN_PASSWORD)
            // Never. A daemon has no operator to ask.
            .prompt_user(false)
            .create(&site.path)
            .map_err(|error| sec_error(&error))?;

        // No auto-lock and no lock on sleep: an agent that has been running for
        // a week must not find its own store locked. The keychain is inside a
        // `0700` directory, so locking would add nothing an unprivileged local
        // user could defeat anyway.
        let mut settings = KeychainSettings::new();
        settings.set_lock_on_sleep(false);
        settings.set_lock_interval(None);
        keychain
            .set_settings(&settings)
            .map_err(|error| sec_error(&error))?;

        // `SecKeychainCreate` is documented to take a POSIX path and is
        // expected to use it verbatim; the `-db` suffix `security
        // create-keychain` is known for is appended to a *bare name*, and the
        // name above already carries it. If that expectation is ever wrong the
        // next line fails with a bare `NotFound` on a path nobody would think
        // to look at, so say what actually appeared instead.
        if !site.path.exists() {
            return Err(io::Error::other(format!(
                "SecKeychainCreate reported success but there is no keychain at {}. {} holds {:?}",
                site.path.display(),
                directory.display(),
                std::fs::read_dir(directory)
                    .map(|entries| entries
                        .flatten()
                        .map(|entry| entry.file_name().to_string_lossy().into_owned())
                        .collect::<Vec<_>>())
                    .unwrap_or_default()
            )));
        }

        restrict(site)?;
        Ok(keychain)
    }

    /// Sets a keychain this program created to `0600`.
    ///
    /// Called after creation *and* after every write. A keychain database is
    /// rewritten by `securityd` rather than by this process, and a rewrite that
    /// went through a fresh file would take the umask's mode rather than the
    /// one set at creation — which is the mode this store's entire access
    /// control rests on for a rooted keychain, and which
    /// `the_guard_is_0600_and_its_directory_is_0700` asserts.
    ///
    /// Never applied to the System or login keychains: their modes are the
    /// operating system's business, not this program's.
    fn restrict(site: &Site) -> io::Result<()> {
        if site.kind != Kind::Rooted {
            return Ok(());
        }
        std::fs::set_permissions(&site.path, std::fs::Permissions::from_mode(0o600))
    }

    pub(super) fn store(site: &Site, _scope: SecretScope, plaintext: &[u8]) -> io::Result<()> {
        let _no_ui = without_user_interaction();
        let keychain = open(site, true)?.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "there is no keychain at {}. The machine-scoped store needs the System \
                     Keychain, which only root may write; the user-scoped store needs a login \
                     keychain, which exists once the account has logged in.",
                    site.path.display()
                ),
            )
        })?;

        keychain
            .set_generic_password(service(), ITEM, plaintext)
            .map_err(|error| sec_error(&error))?;

        restrict(site)
    }

    pub(super) fn load(site: &Site, _scope: SecretScope) -> io::Result<Option<Vec<u8>>> {
        let _no_ui = without_user_interaction();
        let Some(keychain) = open(site, false)? else {
            return Ok(None);
        };

        match keychain.find_generic_password(service(), ITEM) {
            Ok((password, _item)) => Ok(Some(password.as_ref().to_vec())),
            Err(error) if is_absence(&error) => Ok(None),
            Err(error) => Err(sec_error(&error)),
        }
    }

    pub(super) fn delete(site: &Site) -> io::Result<bool> {
        let _no_ui = without_user_interaction();
        let Some(keychain) = open(site, false)? else {
            return Ok(false);
        };

        match keychain.find_generic_password(service(), ITEM) {
            Ok((password, item)) => {
                // The password buffer holds the value. Drop it before anything
                // else happens, so it exists for as few instructions as it can.
                drop(password);
                // `SecKeychainItem::delete` consumes the item and discards the
                // OSStatus, so the only way to know it worked is to look. An
                // `auth logout` that reported success without removing anything
                // would be a lie told during a credential-disclosure response.
                item.delete();
                match keychain.find_generic_password(service(), ITEM) {
                    Err(error) if is_absence(&error) => Ok(true),
                    Ok(_) => Err(io::Error::other(
                        "the keychain item is still present after being deleted",
                    )),
                    Err(error) => Err(sec_error(&error)),
                }
            }
            Err(error) if is_absence(&error) => Ok(false),
            Err(error) => Err(sec_error(&error)),
        }
    }
}

// ---------------------------------------------------------------------------

#[cfg(all(unix, not(target_os = "macos")))]
mod sys {
    //! A `0600` file, and the systemd credential that takes precedence over it.
    //!
    //! `05-infrastructure.md` gives the Linux machine store as *"`0600` file
    //! plus systemd credentials"*, and the two halves are not alternatives.
    //!
    //! **The file** is what `auth login` writes and what `auth logout` removes.
    //! It holds the token at rest with no encryption, because there is no key
    //! to encrypt it with that a boot-time service could also reach — a key in
    //! a second file is not a key, it is an indirection. Its mode is therefore
    //! the entire access control, which is why it is `0600` inside a `0700`
    //! directory and why [`super::SecretStore::protection`] reports the mode
    //! rather than something more reassuring.
    //!
    //! **The systemd credential** is a *read* path, not a write path. A unit
    //! given `LoadCredentialEncrypted=` has the value decrypted into a private
    //! `ramfs` at `$CREDENTIALS_DIRECTORY`, mounted read-only and visible to
    //! no other unit, and nothing is ever written to the agent's own disk. An
    //! operator who has gone to that trouble should not also have to keep a
    //! plaintext copy beside it, so a credential — when one is present — wins.
    //!
    //! That precedence is the reason `store` and `delete` refuse rather than
    //! pretend. A `store` whose value would be shadowed by the credential on
    //! the very next `load` has not stored anything useful, and an `auth
    //! logout` that removed the file while the credential kept the daemon
    //! authenticated would be a false negative in the one procedure —
    //! `05-infrastructure.md`'s credential-disclosure response — where a false
    //! negative is worst. Both say what the operator has to change instead.
    //!
    //! # Machine scope is `/var/lib`, and that is the point
    //!
    //! `$XDG_DATA_HOME` resolves under `$HOME`, and an account that has never
    //! logged in has no `$HOME` to speak of; `$XDG_RUNTIME_DIR` is cleared when
    //! the session ends, which is exactly the event a boot-time service starts
    //! before. `/var/lib/runner-manager` belongs to no session and survives a
    //! reboot, which is the whole requirement.

    use std::io::{self, Write as _};
    use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _, PermissionsExt as _};
    use std::path::{Path, PathBuf};

    use super::{
        APPLICATION, CREDENTIALS_DIRECTORY, DIRECTORY, ITEM, ORGANIZATION, QUALIFIER,
        SYSTEMD_CREDENTIAL, SecretScope, TEMP_PREFIX, overwrite, sweep_temporaries,
        trim_trailing_ascii_whitespace,
    };

    /// Where a machine-scoped store lives. Not under any home directory and
    /// not under any runtime directory; see the module documentation.
    /// The FHS directory for state a program owns; the product's own segment
    /// is [`APPLICATION`], not a second spelling of it.
    const MACHINE_PREFIX: &str = "/var/lib";

    /// The file, and the systemd credential that outranks it.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(super) struct Site {
        file: PathBuf,
        credential: Option<PathBuf>,
    }

    impl Site {
        /// Points this site at a credentials directory the caller names.
        pub(super) fn with_credentials_directory(mut self, directory: &Path) -> Self {
            self.credential = Some(directory.join(SYSTEMD_CREDENTIAL));
            self
        }

        /// The systemd credential this site would read, if it has one.
        pub(super) fn credential(&self) -> Option<&Path> {
            self.credential.as_deref()
        }
    }

    /// `$CREDENTIALS_DIRECTORY/<name>`, when systemd set one.
    fn credential_from_environment() -> Option<PathBuf> {
        std::env::var_os(CREDENTIALS_DIRECTORY)
            .filter(|value| !value.is_empty())
            .map(|value| PathBuf::from(value).join(SYSTEMD_CREDENTIAL))
    }

    pub(super) fn standard_site(scope: SecretScope) -> Result<Site, String> {
        match scope {
            SecretScope::Machine => Ok(Site {
                file: Path::new(MACHINE_PREFIX)
                    .join(APPLICATION)
                    .join(DIRECTORY)
                    .join(ITEM),
                credential: credential_from_environment(),
            }),
            SecretScope::User => {
                let root = directories::ProjectDirs::from(QUALIFIER, ORGANIZATION, APPLICATION)
                    .ok_or_else(|| {
                        "the operating system reports no home directory for this account, \
                             so the user-scoped store cannot be resolved. A service account \
                             configured with no profile normally hits this; use the \
                             machine-scoped store, which is what --start-at boot installs."
                            .to_string()
                    })?
                    .data_local_dir()
                    .to_path_buf();
                Ok(Site {
                    file: root.join(DIRECTORY).join(ITEM),
                    // A user-scoped store is deliberately not for a service, so
                    // it never consults a service's credentials.
                    credential: None,
                })
            }
        }
    }

    pub(super) fn rooted_site(scope: SecretScope, root: &Path) -> Result<Site, String> {
        // A directory per scope. A standard site gets its separation from the
        // root -- `/var/lib` against `$XDG_DATA_HOME` -- and under one
        // caller-named root there is none, so two stores would share a file
        // and `auth logout` under either scope would purge both.
        Ok(Site {
            file: root.join(DIRECTORY).join(scope.as_str()).join(ITEM),
            credential: None,
        })
    }

    pub(super) fn describe(site: &Site) -> String {
        match &site.credential {
            Some(credential) => format!(
                "0600 file at {} (superseded by the systemd credential at {})",
                site.file.display(),
                credential.display()
            ),
            None => format!("0600 file at {}", site.file.display()),
        }
    }

    pub(super) fn guard(site: &Site) -> PathBuf {
        // The object that actually holds the value being read. When systemd
        // supplied one, that is its credential file in the unit's private
        // ramfs, and reporting the agent's own file instead would describe the
        // protection of something nothing reads.
        match &site.credential {
            Some(credential) if credential.exists() => credential.clone(),
            _ => site.file.clone(),
        }
    }

    /// The refusal both `store` and `delete` owe an operator whose unit
    /// supplies a credential.
    fn shadowed_by_credential(site: &Site, verb: &str) -> Option<io::Error> {
        let credential = site.credential.as_ref()?;
        if !credential.exists() {
            return None;
        }
        Some(io::Error::other(format!(
            "this process was started with the systemd credential `{SYSTEMD_CREDENTIAL}`, which \
             takes precedence over {}. {verb} Change the credential in the unit that supplies \
             it -- `systemd-creds` and `LoadCredentialEncrypted=` -- and restart the service.",
            site.file.display()
        )))
    }

    pub(super) fn store(site: &Site, _scope: SecretScope, plaintext: &[u8]) -> io::Result<()> {
        if let Some(error) = shadowed_by_credential(
            site,
            "A token written here would be shadowed by it on the very next load, so nothing \
             was written.",
        ) {
            return Err(error);
        }

        let directory = site
            .file
            .parent()
            .ok_or_else(|| io::Error::other("the store path has no parent directory"))?;
        // `0700` through `mkdir(2)` rather than a following `chmod`, exactly as
        // `crate::paths::AppPaths::create_all` argues; and then set explicitly,
        // because `mkdir` applies the umask and a directory that was already
        // there may predate this rule.
        std::fs::DirBuilder::new()
            .mode(0o700)
            .recursive(true)
            .create(directory)?;
        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))?;

        let temporary = directory.join(format!("{TEMP_PREFIX}{}.tmp", uuid::Uuid::new_v4()));
        let written = (|| -> io::Result<()> {
            // `mode` is applied by `open(2)`, so the file never exists at any
            // other permissions; `create_new` makes it exclusive, so a path
            // pre-created by another account is an error rather than a file
            // this process writes a token into.
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temporary)?;
            file.write_all(plaintext)?;
            file.flush()?;
            file.sync_all()
        })();
        if let Err(error) = written {
            let _ = std::fs::remove_file(&temporary);
            return Err(error);
        }

        if let Err(error) = std::fs::rename(&temporary, &site.file) {
            let _ = std::fs::remove_file(&temporary);
            return Err(error);
        }

        // Best effort: without it the rename can still be lost to a power cut
        // that the file's own `sync_all` survived. Not worth failing a store
        // that has already succeeded.
        if let Ok(handle) = std::fs::File::open(directory) {
            let _ = handle.sync_all();
        }
        Ok(())
    }

    pub(super) fn load(site: &Site, _scope: SecretScope) -> io::Result<Option<Vec<u8>>> {
        if let Some(credential) = &site.credential {
            match std::fs::read(credential) {
                // Trimmed, and *only* here. The operator produced this file
                // with `systemd-creds encrypt`, and `echo`, `printf '%s\n'` and
                // every text editor leave a newline on the end. Byte for byte
                // that newline becomes part of the token and fails much later
                // inside an `Authorization` header, where it reads as a bad
                // credential rather than as a bad read.
                Ok(bytes) => return Ok(Some(trim_trailing_ascii_whitespace(bytes))),
                // No credential of that name: fall through to the file. A unit
                // can be given credentials without being given this one.
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }

        // Not trimmed. `store` writes the value verbatim and with no newline,
        // so anything trailing here is corruption rather than formatting, and
        // silently repairing it would hide the one thing `Corrupt` exists to
        // report.
        match std::fs::read(&site.file) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }

    pub(super) fn delete(site: &Site) -> io::Result<bool> {
        let shadowed = shadowed_by_credential(
            site,
            "The file below was removed, but the credential is still supplying a token and \
             this host is not purged.",
        );

        let removed = overwrite_then_remove(&site.file)?;
        if let Some(directory) = site.file.parent() {
            sweep_temporaries(directory);
        }

        match shadowed {
            Some(error) => Err(error),
            None => Ok(removed),
        }
    }

    /// Zeroes the file's bytes, then unlinks it.
    ///
    /// The zero fill is [`overwrite`], which lives in the parent module so that
    /// it is a function a test can watch rather than a side effect inside a
    /// delete; its documentation carries the "best effort, not a claim"
    /// reasoning in full.
    ///
    /// Not being able to overwrite is not a reason to skip the unlink. The
    /// unlink is the part that matters, it may still succeed, and a store that
    /// refused to purge because it could not scrub first would fail `auth
    /// logout` in exactly the situation where finishing it matters most.
    fn overwrite_then_remove(path: &Path) -> io::Result<bool> {
        let _ = overwrite(path);

        match std::fs::remove_file(path) {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        }
    }
}

// ---------------------------------------------------------------------------
// The Linux-only half of the surface
// ---------------------------------------------------------------------------

/// Systemd credentials, which exist on no other platform.
///
/// A separate `impl` block rather than a cross-platform method that does
/// nothing on two of three operating systems: a caller that names
/// [`PlatformSecretStore::with_credentials_directory`] is writing code that
/// only means something on Linux, and it should not compile anywhere else.
#[cfg(all(unix, not(target_os = "macos")))]
impl PlatformSecretStore {
    /// Points this store at a systemd credentials directory the caller names,
    /// instead of the one `$CREDENTIALS_DIRECTORY` named.
    ///
    /// [`PlatformSecretStore::standard`] already reads the environment
    /// variable, so a daemon started by systemd needs none of this. It is here
    /// for the two callers that cannot use the environment: a test, which must
    /// not mutate a process-wide variable that every other test is reading at
    /// the same time, and `service install`, which resolves what the unit it is
    /// about to write will set.
    #[must_use]
    pub fn with_credentials_directory(mut self, directory: impl AsRef<Path>) -> Self {
        self.site = self.site.with_credentials_directory(directory.as_ref());
        self
    }

    /// The systemd credential this store reads before it reads its own file,
    /// when it has one.
    #[must_use]
    pub fn credential_path(&self) -> Option<&Path> {
        self.site.credential()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use tempfile::TempDir;

    /// Shaped like a real `ghu_` user access token and unmistakably not one.
    ///
    /// **Assembled at run time from fragments on purpose.** The whole literal
    /// therefore appears in no source file and in no compiled artifact, which
    /// is what lets `tests/no_token_outside_the_store.rs` scan this repository
    /// — `target/` included — and treat any hit as a real leak rather than as
    /// its own test data. A `const` here, or a `concat!`, would be folded into
    /// the binary and would make that scan meaningless.
    fn fixture_token() -> SecretString {
        SecretString::from(format!("{}{}", "ghu_", "d2FixtureNotARealCredential000000"))
    }

    /// A second, equally fake token, for the tests that need two.
    fn other_token() -> SecretString {
        SecretString::from(format!("{}{}", "ghu_", "d2SecondFixtureNotARealOne000000"))
    }

    fn exposed(secret: &SecretString) -> String {
        secret.expose_secret().to_string()
    }

    fn rooted(scope: SecretScope, root: &TempDir) -> PlatformSecretStore {
        PlatformSecretStore::rooted_at(scope, root.path()).expect("a rooted store resolves")
    }

    fn stored(store: &PlatformSecretStore) -> String {
        exposed(
            &store
                .load()
                .expect("the store is readable")
                .expect("a value was stored"),
        )
    }

    // -----------------------------------------------------------------------
    // The scope is a function of the start mode, in both directions
    // -----------------------------------------------------------------------

    #[test]
    fn the_scope_is_decided_by_the_start_mode() {
        assert_eq!(
            SecretScope::for_start_mode(StartMode::Boot),
            SecretScope::Machine,
            "a service that starts at boot has no login session to read a user-scoped store from"
        );
        assert_eq!(
            SecretScope::for_start_mode(StartMode::Login),
            SecretScope::User
        );
    }

    #[test]
    fn every_scope_names_the_start_mode_it_is_the_answer_to() {
        for scope in [SecretScope::Machine, SecretScope::User] {
            assert_eq!(SecretScope::for_start_mode(scope.start_mode()), scope);
        }
        for mode in [StartMode::Boot, StartMode::Login] {
            assert_eq!(SecretScope::for_start_mode(mode).start_mode(), mode);
        }
    }

    #[test]
    fn for_start_mode_opens_the_store_that_start_mode_obliges() {
        for mode in [StartMode::Boot, StartMode::Login] {
            let Ok(store) = PlatformSecretStore::for_start_mode(mode) else {
                // Resolution needs a home directory or a %ProgramData%. A host
                // with neither cannot run the product at all, and saying so is
                // more useful than a panic that names neither.
                panic!("the standard store for --start-at {mode} could not be resolved");
            };
            assert_eq!(store.scope(), SecretScope::for_start_mode(mode));
        }
    }

    // -----------------------------------------------------------------------
    // Store, load, delete -- both variants
    // -----------------------------------------------------------------------

    #[test]
    fn a_machine_scoped_store_round_trips() {
        let root = TempDir::new().expect("a temporary directory");
        let store = rooted(SecretScope::Machine, &root);
        let token = fixture_token();

        assert!(
            store
                .load()
                .expect("an empty store reads cleanly")
                .is_none(),
            "nothing is stored before the first `auth login`"
        );

        store.store(&token).expect("the token is stored");
        assert_eq!(stored(&store), exposed(&token));

        assert_eq!(
            store.delete().expect("the token is purged"),
            Removal::Removed
        );
        assert!(
            store
                .load()
                .expect("a purged store reads cleanly")
                .is_none()
        );
    }

    #[test]
    fn a_user_scoped_store_round_trips() {
        let root = TempDir::new().expect("a temporary directory");
        let store = rooted(SecretScope::User, &root);
        let token = fixture_token();

        store.store(&token).expect("the token is stored");
        assert_eq!(stored(&store), exposed(&token));
        assert_eq!(
            store.delete().expect("the token is purged"),
            Removal::Removed
        );
        assert!(
            store
                .load()
                .expect("a purged store reads cleanly")
                .is_none()
        );
    }

    #[test]
    fn the_two_variants_do_not_share_a_value() {
        // Both under one root, because that is the arrangement most likely to
        // let them collide by accident.
        let root = TempDir::new().expect("a temporary directory");
        let machine = rooted(SecretScope::Machine, &root);
        let user = rooted(SecretScope::User, &root);

        machine.store(&fixture_token()).expect("stored");
        user.store(&other_token()).expect("stored");

        assert_eq!(stored(&machine), exposed(&fixture_token()));
        assert_eq!(stored(&user), exposed(&other_token()));

        machine.delete().expect("purged");
        assert!(
            machine.load().expect("readable").is_none(),
            "the machine store is empty"
        );
        assert_eq!(
            stored(&user),
            exposed(&other_token()),
            "purging one variant must not purge the other; `auth logout` under \
             --start-at boot has no business touching a user-scoped store"
        );
    }

    #[test]
    fn storing_again_replaces_the_value() {
        let root = TempDir::new().expect("a temporary directory");
        let store = rooted(SecretScope::Machine, &root);

        store.store(&fixture_token()).expect("stored");
        store.store(&other_token()).expect("stored again");

        assert_eq!(
            stored(&store),
            exposed(&other_token()),
            "a re-issued token replaces the old one rather than being refused"
        );
    }

    // -----------------------------------------------------------------------
    // Absence is not an error, and delete is idempotent
    // -----------------------------------------------------------------------

    #[test]
    fn a_load_after_delete_reports_absence_rather_than_a_failure() {
        let root = TempDir::new().expect("a temporary directory");
        let store = rooted(SecretScope::Machine, &root);
        store.store(&fixture_token()).expect("stored");
        store.delete().expect("purged");

        // Phrased as a match rather than as `is_none`, because the property
        // under test is which *arm* the caller lands in. An `Err` here is the
        // failure the Definition of Done names: "a load after delete reports
        // absence rather than an error that a caller might mistake for a
        // transient failure".
        match store.load() {
            Ok(None) => {}
            Ok(Some(_)) => panic!("the value survived a delete"),
            Err(error) => panic!("absence was reported as a failure a caller may retry: {error}"),
        }
    }

    #[test]
    fn deleting_what_is_not_there_is_success_and_says_so() {
        let root = TempDir::new().expect("a temporary directory");
        let store = rooted(SecretScope::Machine, &root);

        assert_eq!(
            store
                .delete()
                .expect("purging an empty store is not a failure"),
            Removal::AlreadyAbsent,
            "`auth logout` is run on every host during a credential-disclosure \
             response, including the ones that were never logged in"
        );

        store.store(&fixture_token()).expect("stored");
        assert_eq!(store.delete().expect("purged"), Removal::Removed);
        assert_eq!(
            store.delete().expect("purged again"),
            Removal::AlreadyAbsent
        );
    }

    /// "Delete leaves no recoverable remnant" — stated as the same property on
    /// all three platforms, and checked through whatever *carries* the value on
    /// each.
    ///
    /// The distinction is one CI caught rather than one this test was written
    /// with. A file-backed store keeps the value *in* the guard, so the remnant
    /// question is "is the file gone". A keychain-backed store keeps it in an
    /// item *inside* the guard, and the guard is a database that legitimately
    /// outlives every item it ever held — asserting the keychain disappears
    /// would be asserting that `auth logout` deletes the operator's login
    /// keychain, which would be a bug rather than a purge.
    ///
    /// So the two things asserted everywhere are the two that mean the same
    /// thing everywhere: nothing readable is left, and no byte of the value is
    /// lying in whatever does remain.
    #[test]
    fn deleting_leaves_no_recoverable_remnant() {
        let root = TempDir::new().expect("a temporary directory");
        let store = rooted(SecretScope::Machine, &root);
        store.store(&fixture_token()).expect("stored");

        let guard = store.guard();
        assert!(guard.exists(), "something was written");
        store.delete().expect("purged");

        assert!(
            store
                .load()
                .expect("a purged store reads cleanly")
                .is_none(),
            "the value is still readable through the store's own API"
        );
        if let Ok(bytes) = std::fs::read(&guard) {
            let token = exposed(&fixture_token());
            assert!(
                !bytes
                    .windows(token.len())
                    .any(|window| window == token.as_bytes()),
                "the value is still lying in {} after a purge",
                guard.display()
            );
        }

        // A file-backed store additionally leaves nothing at all: neither the
        // named file, nor a `user-access-token.<uuid>.tmp` from a write that was
        // interrupted, which is the token on disk under a name nobody looks at.
        #[cfg(not(target_os = "macos"))]
        {
            assert!(
                !guard.exists(),
                "the stored value is still at {}",
                guard.display()
            );
            if let Some(directory) = guard.parent()
                && let Ok(entries) = std::fs::read_dir(directory)
            {
                let remnants: Vec<_> = entries
                    .flatten()
                    .map(|entry| entry.file_name().to_string_lossy().into_owned())
                    .filter(|name| name.starts_with("user-access-token"))
                    .collect();
                assert!(
                    remnants.is_empty(),
                    "a purge left {remnants:?} in {}",
                    directory.display()
                );
            }
        }
    }

    /// The negative control for the sweep above: a temporary file from an
    /// interrupted write is a token on disk, and a purge that only removed the
    /// file it was told about would leave it there.
    #[cfg(not(target_os = "macos"))]
    #[test]
    fn a_purge_sweeps_a_temporary_left_by_an_interrupted_write() {
        let root = TempDir::new().expect("a temporary directory");
        let store = rooted(SecretScope::Machine, &root);
        store.store(&fixture_token()).expect("stored");

        let directory = store
            .guard()
            .parent()
            .expect("the guard has a directory")
            .to_path_buf();
        let abandoned = directory.join(format!("{TEMP_PREFIX}00000000-dead-beef.tmp"));
        std::fs::write(&abandoned, exposed(&fixture_token())).expect("planted");

        store.delete().expect("purged");
        assert!(
            !abandoned.exists(),
            "a purge left {} behind, which is the token on disk under a name nobody looks at",
            abandoned.display()
        );
    }

    // -----------------------------------------------------------------------
    // What is not a value
    // -----------------------------------------------------------------------

    #[test]
    fn an_empty_value_is_refused_rather_than_stored() {
        let root = TempDir::new().expect("a temporary directory");
        let store = rooted(SecretScope::Machine, &root);

        let error = store
            .store(&SecretString::from(String::new()))
            .expect_err("an empty value is not a token");
        assert!(matches!(error, SecretStoreError::Store { .. }));
        assert!(
            store.load().expect("readable").is_none(),
            "a refused store wrote nothing"
        );
    }

    #[test]
    fn bytes_that_are_not_a_token_are_reported_as_corrupt_and_not_as_absence() {
        let root = TempDir::new().expect("a temporary directory");
        let store = rooted(SecretScope::Machine, &root);

        // `decode` is the half of the read path that is the same on all three
        // operating systems, and it is reachable here because these tests are a
        // child of the module. The platform half -- a DPAPI blob this key
        // cannot unprotect, a file of raw bytes -- is exercised per OS below.
        let error = store
            .decode(vec![0xff, 0xfe, 0xfd])
            .expect_err("invalid UTF-8 is not a token");
        assert!(
            matches!(error, SecretStoreError::Corrupt { .. }),
            "got {error:?}"
        );
        assert!(
            store.decode(Vec::new()).is_err(),
            "an empty value read back is a truncated write, not an absence"
        );
    }

    #[test]
    fn no_error_this_module_produces_repeats_the_value() {
        let root = TempDir::new().expect("a temporary directory");
        let store = rooted(SecretScope::Machine, &root);
        let token = exposed(&fixture_token());

        // Every variant that can be constructed without a real platform
        // failure, rendered both ways a caller can render one.
        let errors = vec![
            SecretStoreError::Resolve {
                scope: SecretScope::Machine,
                reason: "no %ProgramData%".to_string(),
            },
            store
                .store(&SecretString::from(String::new()))
                .expect_err("empty is refused"),
            store
                .decode(token.clone().into_bytes())
                .err()
                .unwrap_or_else(|| store.corrupt("a placeholder")),
            store.corrupt("the bytes there are not valid UTF-8"),
            store
                .protection()
                .err()
                .unwrap_or_else(|| SecretStoreError::Inspect {
                    scope: SecretScope::Machine,
                    guard: store.guard(),
                    source: crate::process::permissions_summary(std::path::Path::new(
                        "a-path-that-is-not-there",
                    ))
                    .expect_err("a missing path cannot be inspected"),
                }),
        ];

        for error in errors {
            let rendered = format!("{error} / {error:?}");
            assert!(
                !rendered.contains(&token),
                "an error rendered the token: {rendered}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Who can read it
    // -----------------------------------------------------------------------

    #[test]
    fn a_stored_value_is_not_readable_by_an_unprivileged_local_user() {
        for scope in [SecretScope::Machine, SecretScope::User] {
            let root = TempDir::new().expect("a temporary directory");
            let store = rooted(scope, &root);
            store.store(&fixture_token()).expect("stored");

            let protection = store.protection().expect("the guard is inspectable");
            assert!(
                !protection.readable_by_other_local_users(),
                "the {scope}-scoped store is readable by other local users: {protection}"
            );
        }
    }

    /// The negative control for the assertion above.
    ///
    /// A check that only ever returns "not readable" proves nothing, and this
    /// one is the whole of the evidence for a `security_critical` Definition of
    /// Done item. So: take a store that has just passed, loosen the one thing
    /// that was protecting it, and require the same call to report the leak.
    #[test]
    fn the_readability_check_reports_a_guard_that_was_loosened() {
        let root = TempDir::new().expect("a temporary directory");
        let store = rooted(SecretScope::Machine, &root);
        store.store(&fixture_token()).expect("stored");
        let guard = store.guard();

        assert!(
            !store
                .protection()
                .expect("inspectable")
                .readable_by_other_local_users(),
            "the control starts from a store that passes"
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&guard, std::fs::Permissions::from_mode(0o644))
                .expect("the guard can be loosened");
        }
        #[cfg(windows)]
        {
            // Replaced with a file created the ordinary way, which inherits the
            // temporary directory's DACL instead of carrying a protected one of
            // its own. That is exactly the mistake the backend exists to avoid:
            // an inherited DACL is whatever the parent grants, and under
            // `%ProgramData%` the parent grants Builtin Users read.
            std::fs::remove_file(&guard).expect("the guard can be replaced");
            std::fs::write(&guard, b"not a protected file").expect("written");
        }

        let protection = store
            .protection()
            .expect("the loosened guard is still inspectable");
        assert!(
            protection.readable_by_other_local_users(),
            "a loosened guard was reported as safe, so the assertion above proves nothing: \
             {protection}"
        );
    }

    #[test]
    fn the_protection_names_the_object_it_inspected() {
        let root = TempDir::new().expect("a temporary directory");
        let store = rooted(SecretScope::Machine, &root);
        store.store(&fixture_token()).expect("stored");

        let protection = store.protection().expect("inspectable");
        assert_eq!(protection.guard(), store.guard());
        assert!(
            !protection.description().is_empty(),
            "a protection with no description is not a diagnosis"
        );
    }

    // -----------------------------------------------------------------------
    // What `host show` and `service status` print
    // -----------------------------------------------------------------------

    #[test]
    fn the_active_store_is_reported_and_agrees_with_the_start_mode() {
        let root = TempDir::new().expect("a temporary directory");

        for mode in [StartMode::Boot, StartMode::Login] {
            let store = rooted(SecretScope::for_start_mode(mode), &root);
            let active = ActiveStore::of(&store, mode);

            assert_eq!(active.scope(), SecretScope::for_start_mode(mode));
            assert_eq!(active.start_mode(), mode);
            assert!(active.agrees_with_start_mode());

            let rendered = active.to_string();
            assert!(
                rendered.contains(active.scope().as_str()),
                "`host show` must name the variant in use: {rendered}"
            );
            assert!(
                rendered.contains(&mode.to_string()),
                "`service status` must name the start mode: {rendered}"
            );
            assert!(
                !rendered.contains("MISMATCH"),
                "a matching pair must not be reported as a mismatch: {rendered}"
            );
        }
    }

    #[test]
    fn a_store_that_disagrees_with_the_start_mode_says_so() {
        let root = TempDir::new().expect("a temporary directory");
        // The failure this exists to catch: a service switched to `--start-at
        // boot` while the token is still in the operator's user-scoped store.
        // The daemon starts, finds nothing, and the only clue is here.
        let store = rooted(SecretScope::User, &root);
        let active = ActiveStore::of(&store, StartMode::Boot);

        assert!(!active.agrees_with_start_mode());
        let rendered = active.to_string();
        assert!(rendered.contains("MISMATCH"), "{rendered}");
        assert!(rendered.contains("machine"), "{rendered}");
    }

    #[test]
    fn the_reported_location_is_not_the_value() {
        let root = TempDir::new().expect("a temporary directory");
        let store = rooted(SecretScope::Machine, &root);
        store.store(&fixture_token()).expect("stored");

        let token = exposed(&fixture_token());
        let active = ActiveStore::of(&store, StartMode::Boot);
        for rendered in [
            store.location(),
            active.to_string(),
            format!("{store:?}"),
            format!("{active:?}"),
            store.protection().expect("inspectable").to_string(),
        ] {
            assert!(
                !rendered.contains(&token),
                "a report carried the value: {rendered}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Where the standard stores live
    // -----------------------------------------------------------------------

    /// The property that makes a machine-scoped store readable after a reboot,
    /// stated as a location rather than as a hope.
    ///
    /// Every per-user directory on all three operating systems hangs off the
    /// account's home directory, and an account that has never logged in does
    /// not have one mounted. A machine store under `$HOME` would work on the
    /// developer's laptop and fail on the first boot of the machine it was
    /// installed on, which is the failure this assertion exists to make
    /// impossible to introduce.
    #[test]
    fn the_machine_store_is_not_under_the_home_directory() {
        let store = PlatformSecretStore::standard(SecretScope::Machine)
            .expect("the machine store resolves");
        let guard = store.guard();

        let Some(base) = directories::BaseDirs::new() else {
            panic!("this account has no home directory, so the assertion cannot be made");
        };
        assert!(
            !guard.starts_with(base.home_dir()),
            "the machine store at {} is under the home directory {}",
            guard.display(),
            base.home_dir().display()
        );
    }

    #[test]
    fn the_user_store_is_under_the_home_directory() {
        // The mirror of the assertion above, and the reason `--start-at login`
        // means what it says: this store is gone when the operator logs out.
        let store =
            PlatformSecretStore::standard(SecretScope::User).expect("the user store resolves");
        let Some(base) = directories::BaseDirs::new() else {
            panic!("this account has no home directory, so the assertion cannot be made");
        };
        assert!(
            store.guard().starts_with(base.home_dir()),
            "the user store at {} is not under the home directory {}",
            store.guard().display(),
            base.home_dir().display()
        );
    }

    #[test]
    fn the_standard_locations_are_the_documented_ones() {
        let machine = PlatformSecretStore::standard(SecretScope::Machine).expect("resolves");
        let user = PlatformSecretStore::standard(SecretScope::User).expect("resolves");

        #[cfg(windows)]
        {
            let program_data = std::path::PathBuf::from(
                std::env::var_os("ProgramData").expect("Windows sets ProgramData"),
            );
            assert_eq!(
                machine.guard(),
                program_data
                    .join("IvanMurzak")
                    .join("runner-manager")
                    .join("secrets")
                    .join("user-access-token.dpapi")
            );
            assert!(user.location().contains("DPAPI"), "{}", user.location());
        }
        #[cfg(target_os = "macos")]
        {
            assert_eq!(
                machine.guard(),
                std::path::Path::new("/var/db/SystemKey"),
                "the System Keychain's protection is its root-only master key, \
                 not the world-readable database beside it"
            );
            assert!(
                machine
                    .location()
                    .contains("/Library/Keychains/System.keychain"),
                "{}",
                machine.location()
            );
            assert!(
                user.location().contains("login.keychain"),
                "{}",
                user.location()
            );
        }
        #[cfg(all(unix, not(target_os = "macos")))]
        {
            assert_eq!(
                machine.guard(),
                std::path::Path::new("/var/lib/runner-manager/secrets/user-access-token")
            );
            assert!(user.location().contains("0600"), "{}", user.location());
        }
    }

    /// The independent oracle for the identity `secrets.rs` now *borrows* from
    /// [`crate::paths`] rather than spelling out.
    ///
    /// Borrowing removes the drift the reviewer named — two files can no longer
    /// disagree — but it moves the risk rather than removing it: a change in
    /// `paths.rs` now silently moves the secret store as well as the four
    /// application-data directories, and a token that has moved reads as simply
    /// absent. The literals below are the only place in this module that is
    /// *not* derived from those constants, which is exactly what makes them
    /// able to catch such a change.
    #[test]
    fn the_product_identity_is_the_one_paths_defines() {
        assert_eq!(QUALIFIER, "io.github");
        assert_eq!(ORGANIZATION, "IvanMurzak");
        assert_eq!(APPLICATION, "runner-manager");

        #[cfg(target_os = "macos")]
        assert_eq!(
            sys::service(),
            "io.github.IvanMurzak.runner-manager",
            "the keychain service names the product; a change here moves every \
             stored item and the token reads as absent"
        );
    }

    /// Finding 2's replacement, and the whole of what the zero fill claims.
    ///
    /// The test it replaces stored, deleted, and asserted the file was gone —
    /// which is what *removing* it proves too, so
    /// `overwrite`'s `write_all` could have been deleted outright and the suite
    /// would have stayed green. This one observes the fill itself: it reads the
    /// bytes back **before** anything unlinks them, so the subject of the test
    /// cannot be removed without it failing.
    ///
    /// Not `cfg`-gated to Linux, although Linux is the platform whose stored
    /// value is plaintext, because the mechanism is shared and a test that only
    /// a CI leg can run is a test its author never watched fail.
    #[cfg(not(target_os = "macos"))]
    #[test]
    fn overwrite_zeroes_every_byte_and_leaves_the_file_there() {
        let root = TempDir::new().expect("a temporary directory");
        let path = root.path().join("value");
        let token = exposed(&fixture_token());
        std::fs::write(&path, &token).expect("written");

        assert!(overwrite(&path).expect("overwritten"), "the file was there");

        let after = std::fs::read(&path).expect("still there, so the fill is observable");
        assert_eq!(
            after.len(),
            token.len(),
            "the overwrite must not truncate; a shorter file leaves the tail of the old \
             value in the block"
        );
        assert!(
            after.iter().all(|byte| *byte == 0),
            "the file still holds non-zero bytes after an overwrite: {after:?}"
        );
        assert!(
            !after
                .windows(token.len())
                .any(|window| window == token.as_bytes()),
            "the value survived the overwrite"
        );
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn overwriting_what_is_not_there_is_not_a_failure() {
        let root = TempDir::new().expect("a temporary directory");
        assert!(
            !overwrite(&root.path().join("absent")).expect("absence is not an error"),
            "a store that was never written has nothing to scrub"
        );
    }

    /// Finding 6's pure half, run on every leg.
    ///
    /// The systemd credential path that uses this is Linux-only, so its
    /// end-to-end test is too; the decision the trim makes is not
    /// platform-specific, and testing it here is what let this be watched
    /// failing on the machine it was written on.
    #[cfg(not(target_os = "macos"))]
    #[test]
    fn a_trailing_newline_is_not_part_of_the_token() {
        let token = exposed(&fixture_token());

        for suffix in ["\n", "\r\n", "\n\n", " ", "\t\n", ""] {
            let raw = format!("{token}{suffix}").into_bytes();
            assert_eq!(
                trim_trailing_ascii_whitespace(raw),
                token.clone().into_bytes(),
                "a credential written with {suffix:?} on the end yielded a different token"
            );
        }

        // Interior whitespace is left alone. A token has none, and silently
        // rewriting the middle of a value would be a worse bug than the one
        // this fixes.
        let interior = b"gh u_x\n".to_vec();
        assert_eq!(trim_trailing_ascii_whitespace(interior), b"gh u_x".to_vec());

        // A value that is nothing but whitespace becomes empty, which `decode`
        // reports as `Corrupt` rather than as absence.
        assert!(trim_trailing_ascii_whitespace(b"\n\n".to_vec()).is_empty());
    }

    // -----------------------------------------------------------------------
    // Windows
    // -----------------------------------------------------------------------

    #[cfg(windows)]
    mod windows {
        use super::*;
        use crate::secrets::sys::{merge_grants, replacement_sddl, sddl, trustees};

        /// How much a [`DeniedReplace`] takes away.
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        enum AlsoDeny {
            /// Only what denies a *replacing rename*. Creating a file in the
            /// directory still works, exactly as it does for operator B, so the
            /// temporary is still written if the store gets that far.
            Nothing,
            /// Additionally `FILE_ADD_FILE`, so nothing can be created in the
            /// directory at all. What makes
            /// [`the_refusal_is_made_before_anything_is_written`] able to tell
            /// a pre-write refusal from a post-write one.
            Creation,
        }

        /// Reproduces what a second non-administrative operator meets, without
        /// needing a second account, and puts the rights back on **every** path
        /// out — including an unwind.
        ///
        /// **Both denies are required, and finding that out was the point of
        /// running this against the un-fixed code.** Windows grants delete two
        /// ways — `DELETE` on the object, or `FILE_DELETE_CHILD` on its parent
        /// — and `MOVEFILE_REPLACE_EXISTING`, which is what `std::fs::rename`
        /// is on Windows, takes either. Operator B has neither: the file's DACL
        /// names `SY`, `BA` and `OW`, and a stock `%ProgramData%` grants
        /// `BUILTIN\Users` no `DC`. The test process, by contrast, *owns* its
        /// temporary directory and so does hold `FILE_DELETE_CHILD` — with only
        /// the file denied, the rename went through and the simulation
        /// reproduced nothing while looking exactly right.
        ///
        /// # Why the restore is a `Drop` and not a line at the end of the body
        ///
        /// Because a failing assertion unwinds past that line, and what it
        /// leaves behind is not tidy: `Everyone:(D)` denies deleting the guard
        /// and `Everyone:(DC)` denies deleting the directory's children, so
        /// `TempDir::drop` — which ignores removal errors — cannot clean up. A
        /// DPAPI blob of the fixture token would sit in `%TEMP%` under an ACL
        /// ordinary cleanup cannot remove, on exactly the run where somebody is
        /// already debugging a failure.
        struct DeniedReplace {
            file: std::path::PathBuf,
            directory: std::path::PathBuf,
            restored: bool,
        }

        impl DeniedReplace {
            fn new(file: &std::path::Path, directory: &std::path::Path, also: AlsoDeny) -> Self {
                let denied = Self {
                    file: file.to_path_buf(),
                    directory: directory.to_path_buf(),
                    restored: false,
                };
                // Constructed first, so that a failure in any `icacls` below
                // unwinds through this guard's `Drop` and undoes the ones that
                // did take effect.
                icacls(&[&denied.file.display().to_string(), "/deny", "*S-1-1-0:(D)"]);
                icacls(&[
                    &denied.directory.display().to_string(),
                    "/deny",
                    "*S-1-1-0:(DC)",
                ]);
                if also == AlsoDeny::Creation {
                    icacls(&[
                        &denied.directory.display().to_string(),
                        "/deny",
                        "*S-1-1-0:(WD)",
                    ]);
                }
                denied
            }

            /// Puts the rights back now, for a test that needs to go on and
            /// observe the store working again. Idempotent, so [`Drop`] running
            /// afterwards is a no-op.
            fn restore(&mut self) {
                if self.restored {
                    return;
                }
                self.restored = true;
                // `/remove:d` drops every deny ACE this SID has on the object,
                // so one call per object undoes all of the above.
                //
                // Deliberately not asserting: this runs on the unwind path,
                // where a panic would abort the process and replace a readable
                // test failure with one nobody can diagnose.
                for path in [&self.file, &self.directory] {
                    let arguments = [
                        path.display().to_string(),
                        "/remove:d".into(),
                        "*S-1-1-0".into(),
                    ];
                    match run_icacls(&arguments.each_ref().map(String::as_str)) {
                        Ok(output) if output.status.success() => {}
                        other => eprintln!(
                            "could not restore the ACL on {}: {other:?}; {} may survive in \
                             the temporary directory",
                            path.display(),
                            path.display()
                        ),
                    }
                }
            }
        }

        impl Drop for DeniedReplace {
            fn drop(&mut self) {
                self.restore();
            }
        }

        fn run_icacls(arguments: &[&str]) -> std::io::Result<std::process::Output> {
            std::process::Command::new("icacls.exe")
                .args(arguments)
                .output()
        }

        fn icacls(arguments: &[&str]) {
            let output = run_icacls(arguments).expect("icacls is present on every Windows");
            assert!(
                output.status.success(),
                "icacls {arguments:?} failed: {}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }

        /// The DACL string alone, with no OS in the way.
        #[test]
        fn a_replacement_carries_the_previous_owner_and_a_first_write_does_not() {
            for scope in [SecretScope::Machine, SecretScope::User] {
                assert_eq!(
                    replacement_sddl(scope, &[]),
                    sddl(scope),
                    "a first write has nothing to carry, so it gets the constant DACL and \
                     nothing else"
                );
                assert_eq!(
                    replacement_sddl(scope, &["S-1-5-21-1-2-3-1001".to_owned()]),
                    format!("{}(A;;FA;;;S-1-5-21-1-2-3-1001)", sddl(scope)),
                    "one carried grant is one appended ACE"
                );
            }
        }

        /// The second renewal, which is where carrying only the owner undoes
        /// itself.
        ///
        /// After one renewal the file is owned by `LocalSystem` and the
        /// operator is named by the ACE that renewal carried. A mechanism that
        /// rebuilds the DACL from the owner alone reads `S-1-5-18` here, drops
        /// the operator, and locks them out again eight hours after the fix
        /// appeared to work.
        ///
        /// Driving `store` cannot reach this: a test process is one account and
        /// cannot make the owner move. So the rule is tested where it lives.
        #[test]
        fn a_grant_survives_a_renewal_by_an_account_that_is_not_the_previous_owner() {
            let operator = "S-1-5-21-9-8-7-1001";
            let after_one_renewal = format!("{}(A;;FA;;;{operator})", sddl(SecretScope::Machine));

            assert_eq!(
                merge_grants(Some("S-1-5-18"), &after_one_renewal),
                vec![operator.to_owned()],
                "the owner is now LocalSystem, which `SY` already grants; what must survive is \
                 the operator named in the DACL the previous renewal wrote"
            );

            assert_eq!(
                merge_grants(Some(operator), sddl(SecretScope::Machine)),
                vec![operator.to_owned()],
                "and the first renewal, where the operator is still the owner and the DACL \
                 names nobody, carries the same one account"
            );

            assert!(
                merge_grants(None, "").is_empty(),
                "a first write has no owner and no DACL to read, and carries nothing"
            );

            assert_eq!(
                merge_grants(Some(operator), &after_one_renewal),
                vec![operator.to_owned()],
                "an account reachable both ways is named once, so the DACL cannot grow by an \
                 ACE per write"
            );

            // The CI runner's own case, which an ordinary developer machine
            // does not reach: Windows renders a well-known account's ACE by
            // alias, so what the previous renewal wrote as `S-1-5-21-...-500`
            // reads back as `LA`. Carrying only trustees spelled `S-1-` drops
            // it and the operator is locked out one renewal later.
            let after_a_renewal_for_a_builtin =
                format!("{}(A;;FA;;;LA)", sddl(SecretScope::Machine));
            assert_eq!(
                merge_grants(Some("S-1-5-18"), &after_a_renewal_for_a_builtin),
                vec!["LA".to_owned()],
                "a grant is a grant whichever spelling the DACL reads back in"
            );

            assert!(
                merge_grants(None, sddl(SecretScope::Machine)).is_empty(),
                "and the constant DACL's own aliases are not carried, or every write would \
                 double the base"
            );
        }

        /// Every trustee, because after the first replacement one of them is
        /// where the operator's access lives — and Windows chooses the
        /// spelling, not this code.
        #[test]
        fn the_trustee_scan_reads_both_spellings() {
            assert_eq!(
                trustees("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)(A;;FA;;;S-1-5-21-9-8-7-1001)"),
                vec![
                    "SY".to_owned(),
                    "BA".to_owned(),
                    "OW".to_owned(),
                    "S-1-5-21-9-8-7-1001".to_owned(),
                ],
                "the scan reads trustees; deciding which of them are already granted is \
                 `merge_grants`'s job and not this one's"
            );
            assert_eq!(
                trustees("D:P(A;;FA;;;LA)"),
                vec!["LA".to_owned()],
                "an alias is a trustee too, which is what CI's built-in Administrator account \
                 reads back as"
            );
        }

        /// The lockout, as a test: renewal writes as a different account, and
        /// the operator who signed in must still be able to read the store.
        ///
        /// # What this can and cannot reproduce
        ///
        /// A test process is one account, so it cannot *become* `LocalSystem`
        /// and take ownership the way a daemon does. What it pins is the
        /// mechanism that makes that survivable: after a replacement, the
        /// previous owner is named in the DACL by SID rather than left to
        /// `OW` — so when the owner does move, the grant does not move with it.
        ///
        /// Un-fixed, the second description equals the first: `OW` and nothing
        /// else, which is exactly the state that locked an operator out of
        /// their own credential on 2026-08-29.
        ///
        /// # What it asserts, and why not the SID
        ///
        /// That the DACL gains something at the first replacement and then
        /// stops changing. Growth would be an ACE per write; a return to the
        /// constant would be the operator dropped, which is the lockout.
        ///
        /// It deliberately does not name the account. Windows chooses the
        /// spelling: this machine's operator reads back as
        /// `S-1-5-21-…-1001`, and CI's, being the built-in Administrator,
        /// reads back as the alias `LA`. An earlier version of this test
        /// asserted the SID and failed on CI for that reason alone —
        /// and the same assumption was in the code, where it was a real
        /// defect. The spelling-sensitive rule is pinned in
        /// [`the_trustee_scan_reads_both_spellings`] instead.
        #[test]
        fn replacing_a_stored_credential_keeps_the_previous_owners_grant() {
            let root = TempDir::new().expect("a temporary directory");
            let store = rooted(SecretScope::Machine, &root);
            let base = sddl(SecretScope::Machine);

            store.store(&fixture_token()).expect("the first write");
            let first = store
                .protection()
                .expect("the first file's DACL is readable")
                .description()
                .to_string();
            assert_eq!(
                first, base,
                "a first write has nothing to carry forward, so it gets the constant DACL"
            );

            let mut previous: Option<String> = None;
            for round in 1..=3 {
                store.store(&other_token()).expect("the replacement");
                let dacl = store
                    .protection()
                    .expect("the replacement's DACL is readable")
                    .description()
                    .to_string();
                assert_ne!(
                    dacl, base,
                    "write {round}: the account that owned what was replaced must stay granted \
                     explicitly, because a writer under another account takes `OW` with it"
                );
                if let Some(previous) = &previous {
                    assert_eq!(
                        &dacl, previous,
                        "write {round}: and the set must settle -- a DACL that keeps growing is \
                         an ACE per renewal, and one that shrinks back to the constant is the \
                         lockout returning"
                    );
                }
                previous = Some(dacl);
            }

            assert_eq!(
                store
                    .load()
                    .expect("the replacement is readable")
                    .map(|secret| secret.expose_secret().to_string()),
                Some(other_token().expose_secret().to_string()),
                "carrying an ACE forward must not disturb what the store holds"
            );
        }

        /// Denies *reading* the store, which is the state a renewal under a
        /// service account leaves an operator in, and puts the right back on
        /// every path out including an unwind.
        ///
        /// A deny ACE for `Everyone` binds administrators too, which is what
        /// makes this reproducible on CI's elevated runner as well as on an
        /// ordinary developer machine.
        struct DeniedRead {
            file: std::path::PathBuf,
            restored: bool,
        }

        impl DeniedRead {
            fn new(file: &std::path::Path) -> Self {
                let denied = Self {
                    file: file.to_path_buf(),
                    restored: false,
                };
                icacls(&[&denied.file.display().to_string(), "/deny", "*S-1-1-0:(R)"]);
                denied
            }

            fn restore(&mut self) {
                if self.restored {
                    return;
                }
                self.restored = true;
                let arguments = [
                    self.file.display().to_string(),
                    "/remove:d".into(),
                    "*S-1-1-0".into(),
                ];
                // Not asserted: this runs on the unwind path, where a panic
                // would replace a readable failure with an aborted process.
                match run_icacls(&arguments.each_ref().map(String::as_str)) {
                    Ok(output) if output.status.success() => {}
                    other => eprintln!(
                        "could not restore the ACL on {}: {other:?}",
                        self.file.display()
                    ),
                }
            }
        }

        impl Drop for DeniedRead {
            fn drop(&mut self) {
                self.restore();
            }
        }

        /// A store the operator may not read says how to get it back.
        ///
        /// Carrying the previous owner keeps this from *starting*, but it
        /// cannot end it on a host where it already happened: the file grants
        /// nobody but the service and has nothing left in its DACL to carry, so
        /// every renewal rebuilds the same DACL. Without a message the operator
        /// is told `Access is denied` by every command, forever, with no way to
        /// find out that one elevated `takeown` ends it.
        ///
        /// Watched on a real host on 2026-08-30, on 0.1.13, which had the carry
        /// and still could not read its own credential.
        #[test]
        fn a_store_this_account_may_not_read_names_the_command_that_gives_it_back() {
            let root = TempDir::new().expect("a temporary directory");
            let store = rooted(SecretScope::Machine, &root);
            store.store(&fixture_token()).expect("the first write");

            let guard = store.guard();
            let _denied = DeniedRead::new(&guard);

            let error = store
                .load()
                .expect_err("a store this account may not read is not a store it can load");
            let rendered = error.to_string();

            for expected in ["takeown", &guard.display().to_string(), "elevated"] {
                assert!(
                    rendered.contains(expected),
                    "the refusal must name the remedy and the file it applies to. Wanted \
                     {expected:?} in: {rendered}"
                );
            }
            assert!(
                !rendered.contains(fixture_token().expose_secret()),
                "and it must not carry the value it could not read"
            );
        }

        /// Finding 1: a second operator is refused with a remedy, before
        /// anything is written.
        ///
        /// The behaviour is right — one machine-scoped credential per host, and
        /// replacing it is an administrator's call; see the backend's module
        /// documentation for why widening the DACL is the wrong answer. What
        /// this pins is that the refusal *says so*, that it is classifiable as
        /// a permission problem, and that it leaves nothing on disk.
        #[test]
        fn a_second_operator_is_refused_with_a_remedy_and_writes_nothing() {
            let root = TempDir::new().expect("a temporary directory");
            let store = rooted(SecretScope::Machine, &root);
            store
                .store(&fixture_token())
                .expect("the first operator stores");

            let guard = store.guard();
            let directory = guard
                .parent()
                .expect("the guard has a directory")
                .to_path_buf();
            let mut denied = DeniedReplace::new(&guard, &directory, AlsoDeny::Nothing);

            let error = store
                .store(&other_token())
                .expect_err("a value this account may not replace is not a value it may store");

            let rendered = error.to_string();
            for expected in [
                "one machine-scoped credential per host",
                "auth logout",
                "elevated",
                "--start-at login",
                "Nothing was written",
            ] {
                assert!(
                    rendered.contains(expected),
                    "the refusal does not name {expected:?}, so an operator cannot act on \
                     it: {rendered}"
                );
            }
            assert!(
                matches!(
                    &error,
                    SecretStoreError::Store { source, .. }
                        if source.kind() == std::io::ErrorKind::PermissionDenied
                ),
                "a caller cannot classify this as a permission problem: {error:?}"
            );

            // Nothing was written, so the refusal did not also leave a valid
            // machine-decryptable blob of a live token under a name nobody
            // looks at. This is the half the old code got wrong: it found out
            // at the rename, after the blob was already on disk.
            let strays: Vec<_> = std::fs::read_dir(&directory)
                .expect("readable")
                .flatten()
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .filter(|name| name.ends_with(".tmp"))
                .collect();
            assert!(strays.is_empty(), "a refused store left {strays:?}");

            // And the first operator's value is untouched.
            denied.restore();
            assert_eq!(stored(&store), exposed(&fixture_token()));

            // With the denial lifted, the same call succeeds -- which is what
            // makes the assertions above a statement about the denial rather
            // than about the store being broken.
            store
                .store(&other_token())
                .expect("stored once allowed again");
            assert_eq!(stored(&store), exposed(&other_token()));
        }

        /// The ordering the fix is built around: the refusal is made **before**
        /// anything is encrypted or written.
        ///
        /// The test above cannot tell. The rename path re-derives the identical
        /// diagnosis — on `PermissionDenied` it calls `cannot_replace` itself —
        /// so moving the probe back behind the write leaves all five message
        /// assertions and the `kind()` assertion passing, and `discard` removes
        /// the temporary either way, so the `strays` assertion does not catch it
        /// either. The property stated at `store`'s call site and twice in the
        /// module documentation was asserted by nothing: the same shape as the
        /// zero fill that could be deleted with the suite staying green.
        ///
        /// [`AlsoDeny::Creation`] closes that. With `FILE_ADD_FILE` denied on
        /// the directory:
        ///
        /// - a probe that runs **first** still produces the remedy, because it
        ///   only reads the target's ACL, and nothing has been written;
        /// - a probe that runs **after** the write never runs at all, because
        ///   `create_protected_file` dies first with a bare denial that carries
        ///   no remedy in it.
        ///
        /// So this pins the ordering rather than the wording.
        #[test]
        fn the_refusal_is_made_before_anything_is_written() {
            let root = TempDir::new().expect("a temporary directory");
            let store = rooted(SecretScope::Machine, &root);
            store
                .store(&fixture_token())
                .expect("the first operator stores");

            let guard = store.guard();
            let directory = guard
                .parent()
                .expect("the guard has a directory")
                .to_path_buf();
            let _denied = DeniedReplace::new(&guard, &directory, AlsoDeny::Creation);

            let error = store
                .store(&other_token())
                .expect_err("nothing can be created here, so nothing can be stored");

            let rendered = error.to_string();
            for expected in [
                "one machine-scoped credential per host",
                "auth logout",
                "elevated",
                "--start-at login",
                "Nothing was written",
            ] {
                assert!(
                    rendered.contains(expected),
                    "the refusal does not name {expected:?}. With creation denied, the only \
                     way to produce that text is a check that ran BEFORE the write -- so this \
                     message came from `create_protected_file` instead, and the store reached \
                     the write before it refused: {rendered}"
                );
            }
        }

        /// Finding 3: the DPAPI output buffer is zeroed before it is freed.
        ///
        /// Asserted against a buffer Rust owns, because once `LocalFree` has
        /// run there is nothing left to look at. `copy_and_scrub` is the whole
        /// of what `take_blob` does to that buffer before freeing it, so this
        /// is the property and not a rehearsal of it.
        #[test]
        fn the_dpapi_buffer_is_scrubbed_before_it_is_freed() {
            let token = exposed(&fixture_token());
            let mut buffer = token.clone().into_bytes();
            let length = buffer.len();

            // SAFETY: `buffer` is a live allocation of exactly `length` bytes
            // and nothing else refers to it for the duration of the call.
            let copy = unsafe { sys::copy_and_scrub(buffer.as_mut_ptr(), length) };

            assert_eq!(
                copy,
                token.clone().into_bytes(),
                "the caller must still receive the value"
            );
            assert!(
                buffer.iter().all(|byte| *byte == 0),
                "the source buffer still holds the token after the copy, and on the \
                 unprotect path that buffer is handed back to the heap by LocalFree: \
                 {buffer:?}"
            );
        }

        #[test]
        fn a_win32_error_keeps_its_kind_through_the_hresult_wrapper() {
            // ERROR_ACCESS_DENIED as windows-rs reports it: HRESULT 0x80070005.
            // Handed straight to `from_raw_os_error` this is `Uncategorized`,
            // and finding 1's refusal could not be classified by a caller.
            let denied = ::windows::core::Error::from_hresult(::windows::core::HRESULT(
                0x8007_0005_u32 as i32,
            ));
            assert_eq!(
                sys::io_error(&denied).kind(),
                std::io::ErrorKind::PermissionDenied
            );

            // ERROR_FILE_NOT_FOUND, 0x80070002.
            let missing = ::windows::core::Error::from_hresult(::windows::core::HRESULT(
                0x8007_0002_u32 as i32,
            ));
            assert_eq!(sys::io_error(&missing).kind(), std::io::ErrorKind::NotFound);
        }

        #[test]
        fn both_dacls_are_protected_and_name_no_broad_trustee() {
            for scope in [SecretScope::Machine, SecretScope::User] {
                let sddl = sys::sddl(scope);
                assert!(
                    sddl.starts_with("D:P"),
                    "an unprotected DACL inherits whatever %ProgramData% grants, which is \
                     Builtin Users read: {sddl}"
                );
                for broad in ["WD", "AU", "BU", "IU", "AN"] {
                    assert!(
                        !sddl.contains(&format!(";{broad})")),
                        "{scope}: {sddl} names the broad trustee {broad}"
                    );
                }
            }
        }

        #[test]
        fn only_the_machine_dacl_carries_the_local_system_ace() {
            // `process.rs` argues at length that a `SY` ACE adds nothing to the
            // JIT handoff, and it is right there: that file's writer and reader
            // are one process. Here they are not -- `auth login` writes as the
            // operator and the daemon reads as the service account -- so `SY`
            // is load-bearing on the machine store and out of place on the
            // user store, which is deliberately not for a service.
            assert!(sys::sddl(SecretScope::Machine).contains("(A;;FA;;;SY)"));
            assert!(!sys::sddl(SecretScope::User).contains(";SY)"));
        }

        #[test]
        fn the_dacl_on_disk_is_the_one_the_backend_asked_for() {
            let root = TempDir::new().expect("a temporary directory");
            for scope in [SecretScope::Machine, SecretScope::User] {
                let store = rooted(scope, &root);
                store.store(&fixture_token()).expect("stored");

                let description = store.protection().expect("inspectable").description;
                assert!(
                    description.contains("D:P"),
                    "{scope}: the stored file did not keep its protected DACL: {description}"
                );
                assert!(
                    description.contains("FA;;;BA"),
                    "{scope}: an administrator must still be able to clean up: {description}"
                );
                // The one ACE that keeps a *non-administrative* operator able
                // to read back what they just stored. Nothing else in the DACL
                // names them, so if `CreateFileW` had quietly dropped it the
                // round trip would still pass on an administrator's machine and
                // fail on everybody else's.
                assert!(
                    description.contains(";OW)") || description.contains(";S-1-3-4)"),
                    "{scope}: the OWNER RIGHTS ACE did not survive to disk, so a \
                     non-administrative operator cannot read their own token: {description}"
                );
                if scope == SecretScope::Machine {
                    assert!(
                        description.contains("FA;;;SY"),
                        "a LocalSystem daemon must be able to read the machine store: \
                         {description}"
                    );
                }
            }
        }

        #[test]
        fn the_bytes_on_disk_are_not_the_value() {
            let root = TempDir::new().expect("a temporary directory");
            let store = rooted(SecretScope::Machine, &root);
            store.store(&fixture_token()).expect("stored");

            let blob = std::fs::read(store.guard()).expect("the blob is readable");
            let token = exposed(&fixture_token());
            assert!(
                !blob
                    .windows(token.len())
                    .any(|window| window == token.as_bytes()),
                "the DPAPI blob contains the plaintext token"
            );
        }

        #[test]
        fn bytes_that_are_not_a_blob_are_reported_as_corrupt() {
            let root = TempDir::new().expect("a temporary directory");
            let store = rooted(SecretScope::Machine, &root);
            store.store(&fixture_token()).expect("stored");

            // A blob truncated by an interrupted write, or one written by
            // another machine and copied here. Either way DPAPI refuses it, and
            // the caller must be told to purge rather than to retry.
            std::fs::write(store.guard(), b"this is not a DPAPI blob").expect("planted");
            let error = store.load().expect_err("a foreign blob is not a value");
            assert!(
                matches!(error, SecretStoreError::Corrupt { .. }),
                "got {error:?}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Unix -- the mode bits, on both Unixes
    // -----------------------------------------------------------------------

    #[cfg(unix)]
    mod unix {
        use super::*;

        use std::os::unix::fs::PermissionsExt as _;

        fn mode_of(path: &std::path::Path) -> u32 {
            std::fs::metadata(path)
                .unwrap_or_else(|error| panic!("{} is not there: {error}", path.display()))
                .permissions()
                .mode()
                & 0o777
        }

        #[test]
        fn the_guard_is_0600_and_its_directory_is_0700() {
            for scope in [SecretScope::Machine, SecretScope::User] {
                let root = TempDir::new().expect("a temporary directory");
                let store = rooted(scope, &root);
                store.store(&fixture_token()).expect("stored");

                let guard = store.guard();
                assert_eq!(
                    mode_of(&guard),
                    0o600,
                    "{scope}: {} is not 0600",
                    guard.display()
                );
                let directory = guard.parent().expect("the guard has a directory");
                assert_eq!(
                    mode_of(directory),
                    0o700,
                    "{scope}: {} is not 0700",
                    directory.display()
                );
            }
        }
    }

    // -----------------------------------------------------------------------
    // Linux -- systemd credentials
    // -----------------------------------------------------------------------

    #[cfg(all(unix, not(target_os = "macos")))]
    mod linux {
        use super::*;

        use std::os::unix::fs::PermissionsExt as _;

        /// Writes `bytes` where systemd would have put a credential.
        fn plant_credential(directory: &std::path::Path, bytes: &[u8]) -> std::path::PathBuf {
            std::fs::create_dir_all(directory).expect("the credentials directory");
            let path = directory.join(SYSTEMD_CREDENTIAL);
            std::fs::write(&path, bytes).expect("the credential is written");
            // systemd mounts the credentials directory read-only and gives each
            // credential 0400. Reproduced so that the protection assertion sees
            // what production would.
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400))
                .expect("the credential is tightened");
            path
        }

        #[test]
        fn a_systemd_credential_is_read_in_preference_to_the_file() {
            let root = TempDir::new().expect("a temporary directory");
            let credentials = TempDir::new().expect("a credentials directory");

            // The file first, so that reading the credential is a preference
            // rather than the only thing there is to read.
            let plain = rooted(SecretScope::Machine, &root);
            plain.store(&other_token()).expect("stored");

            plant_credential(credentials.path(), exposed(&fixture_token()).as_bytes());
            let store =
                rooted(SecretScope::Machine, &root).with_credentials_directory(credentials.path());

            assert_eq!(
                stored(&store),
                exposed(&fixture_token()),
                "a unit given LoadCredentialEncrypted= must not be overridden by a stale file"
            );
            assert_eq!(
                store.credential_path(),
                Some(credentials.path().join(SYSTEMD_CREDENTIAL).as_path())
            );
            assert!(
                store.location().contains("systemd credential"),
                "`host show` must say where the value is actually coming from: {}",
                store.location()
            );
        }

        /// Finding 6, end to end: what an operator's `systemd-creds encrypt`
        /// actually produces.
        ///
        /// `echo`, `printf '%s\n'` and every text editor leave a newline. Used
        /// byte for byte it becomes part of the token and fails much later
        /// inside an `Authorization` header, where it reads as a bad credential
        /// rather than as a bad read — which is the failure this pins.
        #[test]
        fn a_credential_written_with_a_trailing_newline_yields_the_token_without_it() {
            let root = TempDir::new().expect("a temporary directory");
            let credentials = TempDir::new().expect("a credentials directory");
            let token = exposed(&fixture_token());

            plant_credential(credentials.path(), format!("{token}\n").as_bytes());
            let store =
                rooted(SecretScope::Machine, &root).with_credentials_directory(credentials.path());

            assert_eq!(stored(&store), token);
        }

        /// The file half of the same decision, which must *not* be trimmed.
        ///
        /// `store` writes no newline, so anything trailing in its own file is
        /// corruption rather than formatting, and repairing it silently would
        /// hide the one thing `Corrupt` exists to report.
        #[test]
        fn the_stores_own_file_is_read_back_verbatim() {
            let root = TempDir::new().expect("a temporary directory");
            let store = rooted(SecretScope::Machine, &root);
            store.store(&fixture_token()).expect("stored");

            let token = exposed(&fixture_token());
            std::fs::write(store.guard(), format!("{token}\n")).expect("planted");

            assert_eq!(
                stored(&store),
                format!("{token}\n"),
                "the store's own file is used verbatim; only a systemd credential is trimmed"
            );
        }

        #[test]
        fn a_credentials_directory_without_this_credential_falls_back_to_the_file() {
            let root = TempDir::new().expect("a temporary directory");
            let credentials = TempDir::new().expect("a credentials directory");

            let plain = rooted(SecretScope::Machine, &root);
            plain.store(&fixture_token()).expect("stored");

            // A unit can be given credentials without being given this one.
            std::fs::write(credentials.path().join("something.else"), b"x").expect("written");
            let store =
                rooted(SecretScope::Machine, &root).with_credentials_directory(credentials.path());

            assert_eq!(stored(&store), exposed(&fixture_token()));
        }

        #[test]
        fn the_credential_is_what_protection_inspects_when_there_is_one() {
            let root = TempDir::new().expect("a temporary directory");
            let credentials = TempDir::new().expect("a credentials directory");
            let planted =
                plant_credential(credentials.path(), exposed(&fixture_token()).as_bytes());

            let store =
                rooted(SecretScope::Machine, &root).with_credentials_directory(credentials.path());
            let protection = store.protection().expect("inspectable");

            assert_eq!(protection.guard(), planted);
            assert!(!protection.readable_by_other_local_users(), "{protection}");
        }

        #[test]
        fn storing_under_a_systemd_credential_is_refused_rather_than_shadowed() {
            let root = TempDir::new().expect("a temporary directory");
            let credentials = TempDir::new().expect("a credentials directory");
            plant_credential(credentials.path(), exposed(&fixture_token()).as_bytes());

            // The same site without the credential, so the test can name the
            // file the refusal must not have written.
            let file = rooted(SecretScope::Machine, &root).guard();

            let store =
                rooted(SecretScope::Machine, &root).with_credentials_directory(credentials.path());
            let error = store
                .store(&other_token())
                .expect_err("a write that the next read would ignore is not a write");
            let rendered = error.to_string();
            assert!(rendered.contains(SYSTEMD_CREDENTIAL), "{rendered}");

            // And nothing was written, so the refusal did not also leave a
            // second copy of a token on disk.
            assert!(!file.exists(), "{} was written anyway", file.display());
        }

        #[test]
        fn purging_under_a_systemd_credential_removes_the_file_and_reports_the_remainder() {
            let root = TempDir::new().expect("a temporary directory");
            let credentials = TempDir::new().expect("a credentials directory");

            let plain = rooted(SecretScope::Machine, &root);
            plain.store(&other_token()).expect("stored");
            let file = plain.guard();
            plant_credential(credentials.path(), exposed(&fixture_token()).as_bytes());

            let store =
                rooted(SecretScope::Machine, &root).with_credentials_directory(credentials.path());
            let error = store
                .delete()
                .expect_err("this host is not purged and `auth logout` must not say it is");

            assert!(!file.exists(), "the file it could remove was removed");
            assert!(
                error.to_string().contains(SYSTEMD_CREDENTIAL),
                "the operator has to be told what is still supplying a token: {error}"
            );
        }

        #[test]
        #[serial_test::serial]
        fn the_standard_machine_store_reads_the_credentials_directory_from_the_environment() {
            let credentials = TempDir::new().expect("a credentials directory");

            // SAFETY: `serial_test` guarantees no other test in this binary is
            // running, and this is the only test that touches this variable.
            unsafe {
                std::env::set_var(CREDENTIALS_DIRECTORY, credentials.path());
            }
            let store = PlatformSecretStore::standard(SecretScope::Machine).expect("resolves");
            let resolved = store.credential_path().map(std::path::Path::to_path_buf);

            // SAFETY: as above.
            unsafe {
                std::env::remove_var(CREDENTIALS_DIRECTORY);
            }

            assert_eq!(
                resolved,
                Some(credentials.path().join(SYSTEMD_CREDENTIAL)),
                "a daemon started by systemd gets its credential without being told to"
            );

            let without = PlatformSecretStore::standard(SecretScope::Machine).expect("resolves");
            assert_eq!(
                without.credential_path(),
                None,
                "a daemon started by anything else must not invent one"
            );
        }

        #[test]
        fn a_user_scoped_store_never_consults_a_service_credential() {
            let store = PlatformSecretStore::standard(SecretScope::User).expect("resolves");
            assert_eq!(store.credential_path(), None);
        }
    }
}
