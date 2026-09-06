// owner: a1-wsl-platform-adapter

//! The one non-secret file this feature writes on the Windows side: a record
//! per managed WSL distribution.
//!
//! # It is advisory, and being advisory is what makes it safe
//!
//! `02-target-architecture.md` is explicit: *"the record is advisory: status
//! verifies actual WSL/service state and reports drift. A missing record never
//! licenses deletion inside a distribution."* Everything in the shape of this
//! type follows from that sentence.
//!
//! Nothing here is a source of truth about the distribution. `wsl status` asks
//! WSL whether the distribution is there, asks the Linux service whether it is
//! healthy, and asks Task Scheduler whether the task exists; the record only
//! says *"this workstation believes it manages this one, and here is what it
//! last installed"*. So a record that is stale, hand-edited, or absent
//! degrades a status line and can never cause a deletion.
//!
//! # What it may not contain
//!
//! `03-security-and-lifecycle.md` item 3 lists provider records among the
//! places the credential document must be absent from, and
//! `02-target-architecture.md` adds GitHub JIT configuration and repository
//! policies. Two things enforce that rather than one:
//!
//! * the struct has five fields and none of them could hold a secret; and
//! * it is `#[serde(deny_unknown_fields)]`, so a document that grew a `token`
//!   key — by a hand edit, or by a future version writing one — fails to parse
//!   instead of being read and re-written.
//!
//! The second is the one that matters over time. A field nobody added cannot
//! leak; a field somebody adds later is caught by
//! `a_record_carrying_a_credential_field_is_refused_rather_than_ignored`.
//!
//! # Schema version
//!
//! [`PROVIDER_RECORD_SCHEMA_VERSION`] is written and checked. A record from a
//! *newer* version is refused rather than read on a best-effort basis: this
//! product supports downgrades through `update`, and a 0.4 binary silently
//! half-reading a 0.5 record — then rewriting it, dropping whatever it did not
//! understand — is how the newer install loses state.

use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::WslError;
use super::discovery::{escaped_name_with_digest, validate_distribution_name};
use crate::paths::AppPaths;

/// The schema this version writes and is willing to read.
pub const PROVIDER_RECORD_SCHEMA_VERSION: u32 = 1;

/// The directory, under the config directory, that holds the records.
pub const PROVIDER_RECORD_DIR: &str = "wsl-providers";

/// One managed WSL distribution, as this workstation last saw it.
///
/// Every field is non-secret and every field is checkable against reality.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WslProviderRecord {
    /// The schema this document was written under.
    pub schema_version: u32,
    /// The exact distribution name, as `wsl --list` spells it.
    pub distribution: String,
    /// The Task Scheduler name of the lifecycle task.
    pub task_name: String,
    /// The runner-manager version last installed inside the distribution.
    pub installed_version: String,
    /// When the provider last verified the distribution's actual state.
    pub last_verified: DateTime<Utc>,
}

impl WslProviderRecord {
    /// A record for a distribution this workstation now manages.
    #[must_use]
    pub fn new(
        distribution: impl Into<String>,
        task_name: impl Into<String>,
        installed_version: impl Into<String>,
        at: DateTime<Utc>,
    ) -> Self {
        Self {
            schema_version: PROVIDER_RECORD_SCHEMA_VERSION,
            distribution: distribution.into(),
            task_name: task_name.into(),
            installed_version: installed_version.into(),
            last_verified: at,
        }
    }

    /// The directory the records live in.
    #[must_use]
    pub fn directory(paths: &AppPaths) -> PathBuf {
        paths.config_dir().join(PROVIDER_RECORD_DIR)
    }

    /// Where one distribution's record lives.
    ///
    /// The file name is derived the same way the task name is, by the same
    /// function — [`super::discovery::escaped_name_with_digest`] — so two
    /// distributions whose names escape alike cannot share a file.
    ///
    /// # Errors
    ///
    /// [`WslError::InvalidName`] for a distribution name that cannot be used.
    pub fn path(paths: &AppPaths, distribution: &str) -> Result<PathBuf, WslError> {
        validate_distribution_name(distribution)?;
        Ok(Self::directory(paths).join(format!("{}.toml", escaped_name_with_digest(distribution))))
    }

    /// Reads a distribution's record, if there is one.
    ///
    /// # Errors
    ///
    /// [`WslError::InvalidName`]; [`WslError::Record`] when the file exists
    /// and cannot be read or parsed; [`WslError::RecordSchema`] when it was
    /// written by a version this one does not understand.
    pub fn read(paths: &AppPaths, distribution: &str) -> Result<Option<Self>, WslError> {
        let path = Self::path(paths, distribution)?;
        Self::read_file(&path)
    }

    /// Reads one record file.
    ///
    /// # Errors
    ///
    /// As [`WslProviderRecord::read`].
    pub fn read_file(path: &Path) -> Result<Option<Self>, WslError> {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(WslError::Record {
                    operation: "read",
                    path: path.to_path_buf(),
                    detail: error.to_string(),
                });
            }
        };
        let record: Self = toml::from_str(&text).map_err(|error| WslError::Record {
            operation: "read",
            path: path.to_path_buf(),
            detail: error.to_string(),
        })?;
        if record.schema_version != PROVIDER_RECORD_SCHEMA_VERSION {
            return Err(WslError::RecordSchema {
                path: path.to_path_buf(),
                found: record.schema_version,
                supported: PROVIDER_RECORD_SCHEMA_VERSION,
            });
        }
        Ok(Some(record))
    }

    /// Writes the record, replacing any previous one atomically.
    ///
    /// # Atomic, and why it has to be
    ///
    /// The document is written to a temporary file *in the same directory*,
    /// flushed to disk, and renamed onto its destination — so a reader either
    /// sees the previous record or the new one, never a half-written one. A
    /// truncated record is not a cosmetic problem: it is what
    /// [`WslProviderRecord::read`] would refuse to parse, on a machine whose
    /// provisioning had in fact succeeded.
    ///
    /// # Errors
    ///
    /// [`WslError::InvalidName`] and [`WslError::Record`].
    pub fn write(&self, paths: &AppPaths) -> Result<(), WslError> {
        use std::io::Write as _;

        let path = Self::path(paths, &self.distribution)?;
        let failed = |operation: &'static str, detail: String| WslError::Record {
            operation,
            path: path.clone(),
            detail,
        };
        let text =
            toml::to_string_pretty(self).map_err(|error| failed("encode", error.to_string()))?;
        let directory = Self::directory(paths);
        std::fs::create_dir_all(&directory).map_err(|error| failed("write", error.to_string()))?;

        let mut temporary = tempfile::NamedTempFile::new_in(&directory)
            .map_err(|error| failed("write", error.to_string()))?;
        temporary
            .write_all(text.as_bytes())
            .and_then(|()| temporary.as_file().sync_all())
            .map_err(|error| failed("write", error.to_string()))?;
        // `0644` for the same reason `service::InstallRecord` gives: this is
        // non-secret TOML in a `0700` directory, and a `0600` file written
        // under `sudo` becomes one the operator's own `status` cannot read.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            temporary
                .as_file()
                .set_permissions(std::fs::Permissions::from_mode(0o644))
                .map_err(|error| failed("write", error.to_string()))?;
        }
        temporary
            .persist(&path)
            .map(|_| ())
            .map_err(|error| failed("write", error.error.to_string()))
    }

    /// Removes a distribution's record. Returns whether there was one.
    ///
    /// This is the whole of what `wsl detach` deletes on the Windows side
    /// besides the task: nothing inside the distribution, and nothing else in
    /// the config directory.
    ///
    /// # Errors
    ///
    /// [`WslError::InvalidName`] and [`WslError::Record`].
    pub fn remove(paths: &AppPaths, distribution: &str) -> Result<bool, WslError> {
        let path = Self::path(paths, distribution)?;
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(WslError::Record {
                operation: "remove",
                path,
                detail: error.to_string(),
            }),
        }
    }

    /// Every record this workstation holds, in file-name order.
    ///
    /// A file that does not parse is reported rather than skipped: a config
    /// directory with a damaged record is something an operator should be told
    /// about, not something `wsl list` should quietly show one fewer row for.
    ///
    /// # Errors
    ///
    /// [`WslError::Record`] or [`WslError::RecordSchema`].
    pub fn all(paths: &AppPaths) -> Result<Vec<Self>, WslError> {
        let directory = Self::directory(paths);
        let entries = match std::fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => {
                return Err(WslError::Record {
                    operation: "read",
                    path: directory,
                    detail: error.to_string(),
                });
            }
        };
        let mut paths_found = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|error| WslError::Record {
                operation: "read",
                path: directory.clone(),
                detail: error.to_string(),
            })?;
            let path = entry.path();
            if path
                .extension()
                .is_some_and(|extension| extension == "toml")
            {
                paths_found.push(path);
            }
        }
        paths_found.sort();
        let mut records = Vec::with_capacity(paths_found.len());
        for path in paths_found {
            if let Some(record) = Self::read_file(&path)? {
                records.push(record);
            }
        }
        Ok(records)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-09-06T12:00:00Z")
            .expect("a fixed instant")
            .with_timezone(&Utc)
    }

    fn record(distribution: &str) -> WslProviderRecord {
        WslProviderRecord::new(
            distribution,
            "runner-manager-wsl-Ubuntu-1234abcd",
            "0.4.0",
            at(),
        )
    }

    fn paths() -> (tempfile::TempDir, AppPaths) {
        let root = tempfile::tempdir().expect("a temporary directory");
        let paths = AppPaths::rooted_at(root.path());
        (root, paths)
    }

    // -- Shape ---------------------------------------------------------------

    #[test]
    fn a_record_holds_five_non_secret_facts_and_nothing_else() {
        let text = toml::to_string_pretty(&record("Ubuntu")).expect("encodable");
        let keys: Vec<&str> = text
            .lines()
            .filter_map(|line| line.split_once(" = "))
            .map(|(key, _)| key.trim())
            .collect();
        assert_eq!(
            keys,
            [
                "schema_version",
                "distribution",
                "task_name",
                "installed_version",
                "last_verified",
            ]
        );
    }

    #[test]
    fn a_record_never_mentions_a_credential_a_policy_or_a_jit_configuration() {
        let text = toml::to_string_pretty(&record("Ubuntu"))
            .expect("encodable")
            .to_ascii_lowercase();
        for forbidden in [
            "token",
            "secret",
            "credential",
            "refresh",
            "jit",
            "policy",
            "password",
            "ghu_",
        ] {
            assert!(
                !text.contains(forbidden),
                "the record mentions {forbidden:?}: {text}"
            );
        }
    }

    #[test]
    fn a_record_carrying_a_credential_field_is_refused_rather_than_ignored() {
        // `deny_unknown_fields` is the control that survives a future edit:
        // a version that started writing a token here would fail this crate's
        // own reader rather than round-trip it.
        let document = concat!(
            "schema_version = 1\n",
            "distribution = \"Ubuntu\"\n",
            "task_name = \"runner-manager-wsl-Ubuntu-1234abcd\"\n",
            "installed_version = \"0.4.0\"\n",
            "last_verified = \"2026-09-06T12:00:00Z\"\n",
            "access_token = \"ghu_notARealCredential\"\n",
        );
        let error = toml::from_str::<WslProviderRecord>(document)
            .expect_err("an unknown field must be refused");
        assert!(error.to_string().contains("access_token"), "{error}");
    }

    // -- Files ---------------------------------------------------------------

    #[test]
    fn the_record_lives_under_the_config_directory_and_nowhere_else() {
        let (root, paths) = paths();
        let path = WslProviderRecord::path(&paths, "Ubuntu").expect("a valid name");
        assert!(path.starts_with(paths.config_dir()), "{}", path.display());
        assert!(
            path.parent()
                .is_some_and(|parent| parent.ends_with(PROVIDER_RECORD_DIR))
        );
        assert!(path.to_string_lossy().contains("Ubuntu"));
        drop(root);
    }

    #[test]
    fn two_distributions_whose_names_escape_alike_do_not_share_a_file() {
        let (root, paths) = paths();
        let first = WslProviderRecord::path(&paths, "Debian GNU/Linux").expect("valid");
        let second = WslProviderRecord::path(&paths, "Debian GNU:Linux").expect("valid");
        assert_ne!(first, second);
        drop(root);
    }

    #[test]
    fn a_distribution_name_that_is_not_usable_never_becomes_a_path() {
        let (root, paths) = paths();
        assert!(WslProviderRecord::path(&paths, "").is_err());
        assert!(WslProviderRecord::path(&paths, "--shutdown").is_err());
        assert!(WslProviderRecord::path(&paths, "Ub\u{0}untu").is_err());
        drop(root);
    }

    #[test]
    fn a_name_full_of_path_syntax_still_lands_inside_the_record_directory() {
        // `..`, `/` and `\` are all legal in a WSL distribution name -- WSL
        // itself is happy with `Debian GNU/Linux 12` -- so a file name built
        // from one naively would write outside the record directory. The
        // escaping in `escaped_name_with_digest` is what stops that, and this
        // is the property it exists for.
        let (root, paths) = paths();
        for hostile in [
            "../../escape",
            "..",
            r"C:\Windows\System32",
            "a/b/c",
            "Debian GNU/Linux 12",
        ] {
            let path = WslProviderRecord::path(&paths, hostile)
                .unwrap_or_else(|error| panic!("{hostile:?} is a legal WSL name: {error}"));
            assert_eq!(
                path.parent(),
                Some(WslProviderRecord::directory(&paths).as_path()),
                "{hostile:?} escaped the record directory: {}",
                path.display()
            );
            let stem = path
                .file_stem()
                .expect("a file name")
                .to_string_lossy()
                .into_owned();
            assert!(
                stem.chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')),
                "{hostile:?} left path syntax in the file name {stem}"
            );
        }
        drop(root);
    }

    #[test]
    fn a_written_record_reads_back_exactly() {
        let (root, paths) = paths();
        let written = record("Ubuntu");
        written.write(&paths).expect("written");
        let read = WslProviderRecord::read(&paths, "Ubuntu")
            .expect("readable")
            .expect("present");
        assert_eq!(read, written);
        drop(root);
    }

    #[test]
    fn a_missing_record_is_absence_rather_than_an_error() {
        let (root, paths) = paths();
        assert_eq!(
            WslProviderRecord::read(&paths, "Ubuntu").expect("no error"),
            None
        );
        drop(root);
    }

    #[test]
    fn writing_twice_replaces_and_leaves_no_temporary_file_behind() {
        let (root, paths) = paths();
        record("Ubuntu").write(&paths).expect("written");
        let mut second = record("Ubuntu");
        second.installed_version = "0.5.0".to_string();
        second.write(&paths).expect("written again");

        let read = WslProviderRecord::read(&paths, "Ubuntu")
            .expect("readable")
            .expect("present");
        assert_eq!(read.installed_version, "0.5.0");

        let files: Vec<String> = std::fs::read_dir(WslProviderRecord::directory(&paths))
            .expect("the directory exists")
            .map(|entry| {
                entry
                    .expect("readable")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        assert_eq!(
            files.len(),
            1,
            "an atomic write leaves exactly the record behind: {files:?}"
        );
        assert!(files[0].ends_with(".toml"), "{files:?}");
        drop(root);
    }

    #[test]
    fn a_partly_written_file_is_never_what_a_reader_sees() {
        // The property the temporary-file-plus-rename buys, asserted the only
        // way it can be from one thread: the destination does not exist until
        // it is complete, so a reader that runs before the rename sees
        // absence, and one that runs after sees the whole document.
        let (root, paths) = paths();
        let directory = WslProviderRecord::directory(&paths);
        std::fs::create_dir_all(&directory).expect("create");
        let path = WslProviderRecord::path(&paths, "Ubuntu").expect("valid");
        assert!(!path.exists());
        record("Ubuntu").write(&paths).expect("written");
        assert!(path.exists());
        let text = std::fs::read_to_string(&path).expect("readable");
        assert!(text.ends_with('\n'), "the document is complete: {text:?}");
        toml::from_str::<WslProviderRecord>(&text).expect("and parses");
        drop(root);
    }

    #[test]
    fn removing_a_record_reports_whether_there_was_one_and_removes_nothing_else() {
        let (root, paths) = paths();
        record("Ubuntu").write(&paths).expect("written");
        record("Debian GNU/Linux 12")
            .write(&paths)
            .expect("written");

        assert!(WslProviderRecord::remove(&paths, "Ubuntu").expect("removed"));
        assert!(!WslProviderRecord::remove(&paths, "Ubuntu").expect("already gone"));
        assert!(
            WslProviderRecord::read(&paths, "Debian GNU/Linux 12")
                .expect("readable")
                .is_some(),
            "detaching one distribution must not remove another's record"
        );
        drop(root);
    }

    #[test]
    fn listing_returns_every_record_and_nothing_when_there_are_none() {
        let (root, paths) = paths();
        assert!(
            WslProviderRecord::all(&paths)
                .expect("no directory yet")
                .is_empty()
        );
        record("Ubuntu").write(&paths).expect("written");
        record("Alpine").write(&paths).expect("written");
        let all = WslProviderRecord::all(&paths).expect("listed");
        assert_eq!(all.len(), 2);
        let names: Vec<&str> = all
            .iter()
            .map(|record| record.distribution.as_str())
            .collect();
        assert!(
            names.contains(&"Ubuntu") && names.contains(&"Alpine"),
            "{names:?}"
        );
        drop(root);
    }

    // -- Schema --------------------------------------------------------------

    #[test]
    fn a_record_from_a_newer_version_is_refused_rather_than_half_read() {
        let (root, paths) = paths();
        let path = WslProviderRecord::path(&paths, "Ubuntu").expect("valid");
        std::fs::create_dir_all(path.parent().expect("a parent")).expect("create");
        std::fs::write(
            &path,
            concat!(
                "schema_version = 2\n",
                "distribution = \"Ubuntu\"\n",
                "task_name = \"t\"\n",
                "installed_version = \"0.5.0\"\n",
                "last_verified = \"2026-09-06T12:00:00Z\"\n",
            ),
        )
        .expect("written");
        let error = WslProviderRecord::read(&paths, "Ubuntu").expect_err("newer schema");
        let WslError::RecordSchema {
            found, supported, ..
        } = &error
        else {
            panic!("unexpected error: {error:?}");
        };
        assert_eq!(*found, 2);
        assert_eq!(*supported, PROVIDER_RECORD_SCHEMA_VERSION);
        drop(root);
    }

    #[test]
    fn a_new_record_is_written_at_the_current_schema_version() {
        assert_eq!(
            record("Ubuntu").schema_version,
            PROVIDER_RECORD_SCHEMA_VERSION
        );
    }

    #[test]
    fn a_damaged_record_is_reported_rather_than_skipped() {
        let (root, paths) = paths();
        let path = WslProviderRecord::path(&paths, "Ubuntu").expect("valid");
        std::fs::create_dir_all(path.parent().expect("a parent")).expect("create");
        std::fs::write(&path, "this is not TOML at all = = =").expect("written");
        assert!(WslProviderRecord::read(&paths, "Ubuntu").is_err());
        assert!(WslProviderRecord::all(&paths).is_err());
        drop(root);
    }
}
