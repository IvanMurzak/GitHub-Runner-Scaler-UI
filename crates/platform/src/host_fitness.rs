//! Operating-system primitives for `host doctor` and `host prepare`.
//!
//! The check registry, its policy and its wording live in the CLI crate
//! (`cli::doctor`); this module is only the part that has to talk to an
//! operating system: a few read-only probes, the handful of privileged writes
//! `host prepare` makes, the one way each platform asks a person for
//! administrator rights, and the record the daemon leaves when it refuses to
//! start runners on an unfit host.
//!
//! # Every probe is read-only and needs no privilege
//!
//! A probe that cannot answer without administrator rights says so (an
//! [`RegistryError::AccessDenied`], for instance) instead of guessing, and the
//! caller reports the check as unknown. Nothing here writes outside the three
//! `write_*` functions and [`run_elevated`].

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::paths::AppPaths;

// ---------------------------------------------------------------------------
// Privilege
// ---------------------------------------------------------------------------

/// Whether this process already holds administrator rights: an elevated token
/// on Windows, effective uid 0 elsewhere.
#[must_use]
pub fn is_elevated() -> bool {
    sys::is_elevated()
}

/// How an elevated relaunch ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ElevationOutcome {
    /// The elevated process ran and exited with this code.
    Exited(i32),
    /// The person declined the prompt (UAC "No", a cancelled password
    /// dialog, or three wrong `sudo` passwords).
    Refused,
    /// This session cannot show a prompt at all (no desktop, no terminal, no
    /// `sudo`), so nothing was asked.
    Unavailable(String),
}

/// Runs `program args` with administrator rights, asking the person once, and
/// waits for it.
///
/// * **Windows:** `ShellExecuteExW` with the `runas` verb, which shows the UAC
///   prompt. The child's window is hidden; it reports through a file its
///   caller names on the command line.
/// * **macOS:** `sudo` when `terminal` is true (the password is asked for on
///   this terminal), otherwise `osascript … with administrator privileges`,
///   which shows the system's password dialog.
/// * **Linux:** `sudo` when `terminal` is true; otherwise unavailable.
#[must_use]
pub fn run_elevated(program: &Path, args: &[OsString], terminal: bool) -> ElevationOutcome {
    sys::run_elevated(program, args, terminal)
}

/// Quotes one argument for a POSIX shell.
#[must_use]
pub fn quote_posix_argument(argument: &str) -> String {
    format!("'{}'", argument.replace('\'', "'\\''"))
}

/// The AppleScript that runs `command` (already a shell command line) with
/// administrator privileges.
#[must_use]
pub fn administrator_applescript(command: &str) -> String {
    let escaped = command.replace('\\', "\\\\").replace('"', "\\\"");
    format!("do shell script \"{escaped}\" with administrator privileges")
}

// ---------------------------------------------------------------------------
// Read-only facts
// ---------------------------------------------------------------------------

/// Total physical memory, in bytes.
#[must_use]
pub fn physical_memory_bytes() -> Option<u64> {
    sys::physical_memory_bytes()
}

/// The Windows system directory, from the kernel rather than from the
/// writable `%SystemRoot%`: an elevated fix starts `powershell.exe` from it.
///
/// # Errors
/// The system's error when the directory cannot be reported.
#[cfg(windows)]
pub fn system_directory() -> std::io::Result<PathBuf> {
    crate::runner_root::windows_system_directory().map(PathBuf::from)
}

/// Replaces `path` with `bytes` atomically: a temporary file beside it, flushed
/// to disk, then renamed over it, so a reader never sees half a file.
///
/// # Errors
/// The I/O error of any step.
pub fn write_atomically(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    temporary
        .persist(path)
        .map(|_| ())
        .map_err(|error| error.error)
}

/// How a bounded look at a directory went.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Responsiveness {
    /// It answered a `stat` and the first entry of a listing in time.
    Responds,
    /// It did not answer within the deadline: a hung volume (a stalled USB or
    /// NVMe enclosure, a dead network mount).
    Hung,
    /// It answered with an error.
    Failed(String),
}

/// Paths a [`directory_responds`] probe is still blocked on, so a volume that
/// stays hung costs one stuck thread rather than one per probe.
static PROBES_IN_FLIGHT: std::sync::Mutex<Vec<PathBuf>> = std::sync::Mutex::new(Vec::new());

/// Whether `directory` (or, when it does not exist yet, its nearest existing
/// ancestor) answers a `stat` and a one-entry listing within `deadline`.
///
/// The look runs on its own thread because a call into a hung filesystem does
/// not return and cannot be cancelled. That thread is left blocked when the
/// deadline passes, and while it is, later probes of the same path report
/// [`Responsiveness::Hung`] at once instead of stacking more threads on it.
#[must_use]
pub fn directory_responds(directory: &Path, deadline: std::time::Duration) -> Responsiveness {
    let path = directory.to_path_buf();
    {
        let Ok(mut in_flight) = PROBES_IN_FLIGHT.lock() else {
            return Responsiveness::Failed("the probe registry is poisoned".into());
        };
        if in_flight.contains(&path) {
            return Responsiveness::Hung;
        }
        in_flight.push(path.clone());
    }
    let (sender, receiver) = std::sync::mpsc::channel();
    let probed = path.clone();
    let spawned = std::thread::Builder::new()
        .name("runner-root-probe".into())
        .spawn(move || {
            let existing = probed
                .ancestors()
                .find(|ancestor| std::fs::symlink_metadata(ancestor).is_ok())
                .map(Path::to_path_buf);
            let answer = match existing {
                None => Responsiveness::Failed(format!("{} does not exist", probed.display())),
                Some(existing) => match std::fs::read_dir(&existing) {
                    Ok(mut entries) => match entries.next() {
                        Some(Err(error)) => Responsiveness::Failed(error.to_string()),
                        _ => Responsiveness::Responds,
                    },
                    Err(error) => Responsiveness::Failed(error.to_string()),
                },
            };
            if let Ok(mut in_flight) = PROBES_IN_FLIGHT.lock() {
                in_flight.retain(|candidate| *candidate != probed);
            }
            let _ = sender.send(answer);
        });
    if let Err(error) = spawned {
        if let Ok(mut in_flight) = PROBES_IN_FLIGHT.lock() {
            in_flight.retain(|candidate| *candidate != path);
        }
        return Responsiveness::Failed(error.to_string());
    }
    receiver
        .recv_timeout(deadline)
        .unwrap_or(Responsiveness::Hung)
}

/// Whether this process can create a symbolic link inside `directory`.
///
/// Measured rather than inferred: a link is created and removed again. On
/// Windows this answers for the account and token this process runs with,
/// which for the daemon is exactly the account runners inherit; a file link
/// is what `npm`, `pnpm` and `setup-bun` create, and it needs either
/// `SeCreateSymbolicLinkPrivilege` or Developer Mode.
///
/// # Errors
/// The I/O error when the probe's target file cannot even be created, which
/// says nothing about links.
pub fn can_create_symlink(directory: &Path) -> std::io::Result<bool> {
    std::fs::create_dir_all(directory)?;
    let unique = format!(
        ".rm-symlink-probe-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4().simple()
    );
    let target = directory.join(format!("{unique}.target"));
    let link = directory.join(format!("{unique}.link"));
    std::fs::write(&target, b"")?;
    let created = symlink_file(&target, &link);
    let _ = std::fs::remove_file(&link);
    let _ = std::fs::remove_file(&target);
    Ok(created.is_ok())
}

#[cfg(windows)]
fn symlink_file(target: &Path, link: &Path) -> std::io::Result<()> {
    std::os::windows::fs::symlink_file(target, link)
}

#[cfg(unix)]
fn symlink_file(target: &Path, link: &Path) -> std::io::Result<()> {
    std::os::unix::fs::symlink(target, link)
}

/// Finds `tool` on `path` the way a shell would, including `PATHEXT` on
/// Windows. A name holding a path separator is never searched.
#[must_use]
pub fn find_on_path(tool: &str, path: &OsStr) -> Option<PathBuf> {
    if tool.is_empty() || tool.contains(['/', '\\']) {
        return None;
    }
    let extensions: Vec<String> = if cfg!(windows) {
        let pathext = std::env::var("PATHEXT").unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".into());
        // A bare name is tried as-is only when it already carries an
        // extension: `cmd` and `CreateProcess` never run an extensionless file,
        // and Node.js ships a POSIX `npm` script beside `npm.cmd`.
        let mut list = Vec::new();
        if tool.contains('.') {
            list.push(String::new());
        }
        list.extend(
            pathext
                .split(';')
                .filter(|ext| !ext.is_empty())
                .map(str::to_ascii_lowercase),
        );
        list
    } else {
        vec![String::new()]
    };
    std::env::split_paths(path)
        .filter(|dir| !dir.as_os_str().is_empty())
        .find_map(|dir| {
            extensions.iter().find_map(|extension| {
                let candidate = dir.join(format!("{tool}{extension}"));
                is_executable(&candidate).then_some(candidate)
            })
        })
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::metadata(path)
        .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
}

#[cfg(windows)]
fn is_executable(path: &Path) -> bool {
    std::fs::metadata(path).is_ok_and(|meta| meta.is_file())
}

// ---------------------------------------------------------------------------
// The Windows registry (HKEY_LOCAL_MACHINE only)
// ---------------------------------------------------------------------------

/// Why a registry read or write failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RegistryError {
    /// The key exists and this token may not read (or write) it. Defender's
    /// exclusion list answers this to every non-administrator.
    #[error("access denied")]
    AccessDenied,
    /// Any other failure, with the system's code.
    #[error("{0}")]
    Other(String),
}

/// Reads a `REG_DWORD` under `HKLM\subkey`; `None` when the key or value is
/// absent.
///
/// # Errors
/// [`RegistryError`] when it exists and cannot be read.
pub fn read_registry_dword(subkey: &str, value: &str) -> Result<Option<u32>, RegistryError> {
    sys::read_dword(subkey, value)
}

/// Reads a `REG_SZ` or `REG_EXPAND_SZ` (unexpanded) under `HKLM\subkey`.
///
/// # Errors
/// [`RegistryError`] when it exists and cannot be read.
pub fn read_registry_string(subkey: &str, value: &str) -> Result<Option<String>, RegistryError> {
    sys::read_string(subkey, value)
}

/// The names of every value under `HKLM\subkey`; an empty list when the key
/// does not exist.
///
/// # Errors
/// [`RegistryError::AccessDenied`] when the key may not be read.
pub fn registry_value_names(subkey: &str) -> Result<Vec<String>, RegistryError> {
    sys::value_names(subkey)
}

/// Writes (`Some`) or deletes (`None`) a `REG_DWORD` under `HKLM\subkey`,
/// creating the key when needed. Needs administrator rights.
///
/// # Errors
/// [`RegistryError`] when the write is refused.
pub fn write_registry_dword(
    subkey: &str,
    value: &str,
    data: Option<u32>,
) -> Result<(), RegistryError> {
    sys::write_dword(subkey, value, data)
}

/// Writes (`Some`) or deletes (`None`) a `REG_SZ` under `HKLM\subkey`. Needs
/// administrator rights.
///
/// # Errors
/// [`RegistryError`] when the write is refused.
pub fn write_registry_string(
    subkey: &str,
    value: &str,
    data: Option<&str>,
) -> Result<(), RegistryError> {
    sys::write_string(subkey, value, data)
}

// ---------------------------------------------------------------------------
// The daemon's host-unfit record
// ---------------------------------------------------------------------------

/// The file under `state/` the daemon keeps while it refuses to start runners.
pub const HOST_UNFIT_FILE: &str = "host-unfit.json";
const HOST_UNFIT_SCHEMA_VERSION: u32 = 1;

/// What the daemon recorded the last time a required host check failed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostUnfitRecord {
    pub schema_version: u32,
    /// The first moment of the ongoing refusal.
    pub since: DateTime<Utc>,
    /// When the checks were last evaluated.
    pub checked_at: DateTime<Utc>,
    /// The ids of the required checks that failed.
    pub checks: Vec<String>,
}

fn host_unfit_path(paths: &AppPaths) -> PathBuf {
    paths.state_dir().join(HOST_UNFIT_FILE)
}

/// Records that required checks failed, keeping the first moment of an
/// ongoing refusal.
///
/// # Errors
/// A description of the write failure.
pub fn record_host_unfit(
    paths: &AppPaths,
    checks: &[String],
    at: DateTime<Utc>,
) -> Result<(), String> {
    let since = host_unfit(paths)
        .ok()
        .flatten()
        .map_or(at, |record| record.since);
    let record = HostUnfitRecord {
        schema_version: HOST_UNFIT_SCHEMA_VERSION,
        since,
        checked_at: at,
        checks: checks.to_vec(),
    };
    let path = host_unfit_path(paths);
    let text = serde_json::to_vec_pretty(&record).map_err(|error| error.to_string())?;
    write_atomically(&path, &text)
        .map_err(|error| format!("cannot write {}: {error}", path.display()))
}

/// Removes the record once every required check passes.
///
/// # Errors
/// A description of the failure when the record exists and cannot be removed.
pub fn clear_host_unfit(paths: &AppPaths) -> Result<(), String> {
    let path = host_unfit_path(paths);
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("cannot remove {}: {error}", path.display())),
    }
}

/// The daemon's current refusal, if it has one.
///
/// # Errors
/// A description of the failure when the file exists and cannot be read.
pub fn host_unfit(paths: &AppPaths) -> Result<Option<HostUnfitRecord>, String> {
    let path = host_unfit_path(paths);
    match std::fs::read_to_string(&path) {
        Ok(text) => serde_json::from_str(&text)
            .map(Some)
            .map_err(|error| format!("cannot parse {}: {error}", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!("cannot read {}: {error}", path.display())),
    }
}

// ---------------------------------------------------------------------------
// Windows
// ---------------------------------------------------------------------------

#[cfg(windows)]
mod sys {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStrExt as _;
    use std::path::Path;

    use windows::Win32::Foundation::{
        CloseHandle, ERROR_ACCESS_DENIED, ERROR_CANCELLED, ERROR_FILE_NOT_FOUND,
        ERROR_NO_MORE_ITEMS, ERROR_SUCCESS, HANDLE, WAIT_OBJECT_0, WIN32_ERROR,
    };
    use windows::Win32::Security::{
        GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
    };
    use windows::Win32::System::Registry::{
        HKEY, HKEY_LOCAL_MACHINE, KEY_READ, KEY_SET_VALUE, REG_DWORD, REG_OPTION_NON_VOLATILE,
        REG_SZ, RRF_NOEXPAND, RRF_RT_REG_DWORD, RRF_RT_REG_EXPAND_SZ, RRF_RT_REG_SZ, RegCloseKey,
        RegCreateKeyExW, RegDeleteKeyValueW, RegEnumValueW, RegGetValueW, RegOpenKeyExW,
        RegSetValueExW,
    };
    use windows::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
    use windows::Win32::System::Threading::{
        GetCurrentProcess, GetExitCodeProcess, OpenProcessToken, WaitForSingleObject,
    };
    use windows::Win32::UI::Shell::{
        SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW,
    };
    use windows::core::{PCWSTR, PWSTR};

    use super::{ElevationOutcome, RegistryError};

    /// `SW_HIDE`. Spelled here rather than pulling in the whole
    /// `WindowsAndMessaging` module for one integer.
    const SW_HIDE: i32 = 0;
    /// The longest an elevated fix batch is waited for. Generous: Defender
    /// and `git config` answer in seconds, and a person may take a while to
    /// read the UAC prompt.
    const ELEVATED_WAIT_MS: u32 = 15 * 60 * 1000;

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn registry_error(code: WIN32_ERROR) -> RegistryError {
        if code == ERROR_ACCESS_DENIED {
            RegistryError::AccessDenied
        } else {
            RegistryError::Other(format!("registry error {}", code.0))
        }
    }

    pub(super) fn is_elevated() -> bool {
        let mut token = HANDLE::default();
        // SAFETY: the pseudo-handle from `GetCurrentProcess` needs no closing;
        // `token` is a live out-parameter owned by this frame.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) }.is_err() {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION::default();
        let mut returned = 0u32;
        // SAFETY: `elevation` is a correctly sized `TOKEN_ELEVATION` owned by
        // this frame, and its size is the length passed.
        let queried = unsafe {
            GetTokenInformation(
                token,
                TokenElevation,
                Some((&raw mut elevation).cast()),
                u32::try_from(std::mem::size_of::<TOKEN_ELEVATION>()).unwrap_or(4),
                &raw mut returned,
            )
        };
        // SAFETY: `token` was opened above and is closed exactly once.
        let _ = unsafe { CloseHandle(token) };
        queried.is_ok() && elevation.TokenIsElevated != 0
    }

    pub(super) fn physical_memory_bytes() -> Option<u64> {
        let mut status = MEMORYSTATUSEX {
            dwLength: u32::try_from(std::mem::size_of::<MEMORYSTATUSEX>()).ok()?,
            ..MEMORYSTATUSEX::default()
        };
        // SAFETY: `status` is a correctly sized, length-stamped structure
        // owned by this frame.
        unsafe { GlobalMemoryStatusEx(&raw mut status) }.ok()?;
        Some(status.ullTotalPhys)
    }

    pub(super) fn read_dword(subkey: &str, value: &str) -> Result<Option<u32>, RegistryError> {
        let subkey = wide(subkey);
        let value = wide(value);
        let mut data = 0u32;
        let mut size = 4u32;
        // SAFETY: both names are NUL-terminated and outlive the call; `data`
        // and `size` are live and describe a 4-byte buffer.
        let code = unsafe {
            RegGetValueW(
                HKEY_LOCAL_MACHINE,
                PCWSTR(subkey.as_ptr()),
                PCWSTR(value.as_ptr()),
                RRF_RT_REG_DWORD,
                None,
                Some((&raw mut data).cast()),
                Some(&raw mut size),
            )
        };
        match code {
            ERROR_SUCCESS => Ok(Some(data)),
            ERROR_FILE_NOT_FOUND => Ok(None),
            other => Err(registry_error(other)),
        }
    }

    pub(super) fn read_string(subkey: &str, value: &str) -> Result<Option<String>, RegistryError> {
        let subkey = wide(subkey);
        let value = wide(value);
        let flags = RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ | RRF_NOEXPAND;
        let mut size = 0u32;
        // SAFETY: a size query; both names are NUL-terminated and outlive it.
        let code = unsafe {
            RegGetValueW(
                HKEY_LOCAL_MACHINE,
                PCWSTR(subkey.as_ptr()),
                PCWSTR(value.as_ptr()),
                flags,
                None,
                None,
                Some(&raw mut size),
            )
        };
        match code {
            ERROR_SUCCESS => {}
            ERROR_FILE_NOT_FOUND => return Ok(None),
            other => return Err(registry_error(other)),
        }
        let mut buffer = vec![0u16; (size as usize).div_ceil(2) + 1];
        let mut size = u32::try_from(buffer.len() * 2).unwrap_or(u32::MAX);
        // SAFETY: `buffer` is owned by this frame and `size` is its length in
        // bytes.
        let code = unsafe {
            RegGetValueW(
                HKEY_LOCAL_MACHINE,
                PCWSTR(subkey.as_ptr()),
                PCWSTR(value.as_ptr()),
                flags,
                None,
                Some(buffer.as_mut_ptr().cast()),
                Some(&raw mut size),
            )
        };
        match code {
            ERROR_SUCCESS => {
                let units = (size as usize / 2).min(buffer.len());
                let text = String::from_utf16_lossy(&buffer[..units]);
                Ok(Some(text.trim_end_matches('\0').to_owned()))
            }
            ERROR_FILE_NOT_FOUND => Ok(None),
            other => Err(registry_error(other)),
        }
    }

    pub(super) fn value_names(subkey: &str) -> Result<Vec<String>, RegistryError> {
        let subkey = wide(subkey);
        let mut key = HKEY::default();
        // SAFETY: `subkey` is NUL-terminated and `key` is a live out-parameter.
        let code = unsafe {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                PCWSTR(subkey.as_ptr()),
                None,
                KEY_READ,
                &raw mut key,
            )
        };
        match code {
            ERROR_SUCCESS => {}
            ERROR_FILE_NOT_FOUND => return Ok(Vec::new()),
            other => return Err(registry_error(other)),
        }
        let mut names = Vec::new();
        let mut index = 0u32;
        let result = loop {
            // 16,383 characters is the documented maximum value-name length.
            let mut name = vec![0u16; 16_384];
            let mut length = u32::try_from(name.len()).unwrap_or(u32::MAX);
            // SAFETY: `name` is owned by this frame and `length` is its size
            // in characters; every other out-parameter is omitted.
            let code = unsafe {
                RegEnumValueW(
                    key,
                    index,
                    Some(PWSTR(name.as_mut_ptr())),
                    &raw mut length,
                    None,
                    None,
                    None,
                    None,
                )
            };
            match code {
                ERROR_SUCCESS => {
                    names.push(String::from_utf16_lossy(&name[..length as usize]));
                    index += 1;
                }
                ERROR_NO_MORE_ITEMS => break Ok(names),
                other => break Err(registry_error(other)),
            }
        };
        // SAFETY: `key` was opened above and is closed exactly once.
        let _ = unsafe { RegCloseKey(key) };
        result
    }

    fn write_value(
        subkey: &str,
        value: &str,
        data: Option<(windows::Win32::System::Registry::REG_VALUE_TYPE, Vec<u8>)>,
    ) -> Result<(), RegistryError> {
        let subkey_wide = wide(subkey);
        let value_wide = wide(value);
        let Some((kind, bytes)) = data else {
            // SAFETY: both names are NUL-terminated and outlive the call.
            let code = unsafe {
                RegDeleteKeyValueW(
                    HKEY_LOCAL_MACHINE,
                    PCWSTR(subkey_wide.as_ptr()),
                    PCWSTR(value_wide.as_ptr()),
                )
            };
            return match code {
                ERROR_SUCCESS | ERROR_FILE_NOT_FOUND => Ok(()),
                other => Err(registry_error(other)),
            };
        };
        let mut key = HKEY::default();
        // SAFETY: `subkey_wide` is NUL-terminated; `key` is a live
        // out-parameter; no class, security attributes or disposition.
        let code = unsafe {
            RegCreateKeyExW(
                HKEY_LOCAL_MACHINE,
                PCWSTR(subkey_wide.as_ptr()),
                None,
                PCWSTR::null(),
                REG_OPTION_NON_VOLATILE,
                KEY_SET_VALUE,
                None,
                &raw mut key,
                None,
            )
        };
        if code != ERROR_SUCCESS {
            return Err(registry_error(code));
        }
        // SAFETY: `key` is open for `KEY_SET_VALUE`; the value name is
        // NUL-terminated and `bytes` outlives the call.
        let code =
            unsafe { RegSetValueExW(key, PCWSTR(value_wide.as_ptr()), None, kind, Some(&bytes)) };
        // SAFETY: `key` was opened above and is closed exactly once.
        let _ = unsafe { RegCloseKey(key) };
        if code == ERROR_SUCCESS {
            Ok(())
        } else {
            Err(registry_error(code))
        }
    }

    pub(super) fn write_dword(
        subkey: &str,
        value: &str,
        data: Option<u32>,
    ) -> Result<(), RegistryError> {
        write_value(
            subkey,
            value,
            data.map(|data| (REG_DWORD, data.to_le_bytes().to_vec())),
        )
    }

    pub(super) fn write_string(
        subkey: &str,
        value: &str,
        data: Option<&str>,
    ) -> Result<(), RegistryError> {
        write_value(
            subkey,
            value,
            data.map(|text| {
                let bytes = wide(text)
                    .iter()
                    .flat_map(|unit| unit.to_le_bytes())
                    .collect();
                (REG_SZ, bytes)
            }),
        )
    }

    pub(super) fn run_elevated(
        program: &Path,
        args: &[OsString],
        _terminal: bool,
    ) -> ElevationOutcome {
        let file: Vec<u16> = program
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let parameters = args
            .iter()
            .map(|argument| crate::service::quote_argument(&argument.to_string_lossy()))
            .collect::<Vec<_>>()
            .join(" ");
        let parameters = wide(&parameters);
        let verb = wide("runas");
        let mut info = SHELLEXECUTEINFOW {
            cbSize: u32::try_from(std::mem::size_of::<SHELLEXECUTEINFOW>()).unwrap_or(0),
            fMask: SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC,
            lpVerb: PCWSTR(verb.as_ptr()),
            lpFile: PCWSTR(file.as_ptr()),
            lpParameters: PCWSTR(parameters.as_ptr()),
            nShow: SW_HIDE,
            ..SHELLEXECUTEINFOW::default()
        };
        // SAFETY: every string in `info` is NUL-terminated and outlives the
        // call; `info` is correctly sized and owned by this frame.
        if let Err(error) = unsafe { ShellExecuteExW(&raw mut info) } {
            #[allow(clippy::cast_sign_loss)]
            let code = (error.code().0 as u32) & 0xffff;
            return if code == ERROR_CANCELLED.0 {
                ElevationOutcome::Refused
            } else {
                ElevationOutcome::Unavailable(format!(
                    "Windows could not show the administrator prompt: {}",
                    error.message()
                ))
            };
        }
        if info.hProcess.is_invalid() {
            return ElevationOutcome::Unavailable(
                "Windows started no elevated process to wait for".into(),
            );
        }
        // SAFETY: `hProcess` is a live process handle returned because
        // `SEE_MASK_NOCLOSEPROCESS` was set; it is closed exactly once below.
        let waited = unsafe { WaitForSingleObject(info.hProcess, ELEVATED_WAIT_MS) };
        let mut code = 1u32;
        let outcome = if waited == WAIT_OBJECT_0 {
            // SAFETY: as above; `code` is a live out-parameter.
            match unsafe { GetExitCodeProcess(info.hProcess, &raw mut code) } {
                #[allow(clippy::cast_possible_wrap)]
                Ok(()) => ElevationOutcome::Exited(code as i32),
                Err(error) => ElevationOutcome::Unavailable(format!(
                    "the elevated process's exit code could not be read: {}",
                    error.message()
                )),
            }
        } else {
            ElevationOutcome::Unavailable(
                "the elevated process did not finish within 15 minutes".into(),
            )
        };
        // SAFETY: closed exactly once.
        let _ = unsafe { CloseHandle(info.hProcess) };
        outcome
    }
}

// ---------------------------------------------------------------------------
// macOS and Linux
// ---------------------------------------------------------------------------

#[cfg(unix)]
mod sys {
    use std::ffi::OsString;
    use std::path::Path;
    use std::process::Command;

    use super::{ElevationOutcome, RegistryError};

    pub(super) fn is_elevated() -> bool {
        // SAFETY: `geteuid` takes no argument and cannot fail.
        unsafe { libc::geteuid() == 0 }
    }

    #[cfg(target_os = "macos")]
    pub(super) fn physical_memory_bytes() -> Option<u64> {
        let mut value = 0u64;
        let mut size = std::mem::size_of::<u64>();
        let name = c"hw.memsize";
        // SAFETY: `name` is NUL-terminated; `value`/`size` describe a live
        // 8-byte buffer owned by this frame; no new value is written.
        let result = unsafe {
            libc::sysctlbyname(
                name.as_ptr(),
                (&raw mut value).cast(),
                &raw mut size,
                std::ptr::null_mut(),
                0,
            )
        };
        (result == 0).then_some(value)
    }

    #[cfg(not(target_os = "macos"))]
    pub(super) fn physical_memory_bytes() -> Option<u64> {
        let text = std::fs::read_to_string("/proc/meminfo").ok()?;
        let line = text.lines().find(|line| line.starts_with("MemTotal:"))?;
        let kib: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
        kib.checked_mul(1024)
    }

    fn unsupported() -> RegistryError {
        RegistryError::Other("the registry exists only on Windows".into())
    }

    pub(super) fn read_dword(_: &str, _: &str) -> Result<Option<u32>, RegistryError> {
        Err(unsupported())
    }

    pub(super) fn read_string(_: &str, _: &str) -> Result<Option<String>, RegistryError> {
        Err(unsupported())
    }

    pub(super) fn value_names(_: &str) -> Result<Vec<String>, RegistryError> {
        Err(unsupported())
    }

    pub(super) fn write_dword(_: &str, _: &str, _: Option<u32>) -> Result<(), RegistryError> {
        Err(unsupported())
    }

    pub(super) fn write_string(_: &str, _: &str, _: Option<&str>) -> Result<(), RegistryError> {
        Err(unsupported())
    }

    fn exit_outcome(
        status: std::io::Result<std::process::ExitStatus>,
        what: &str,
    ) -> ElevationOutcome {
        match status {
            Ok(status) => ElevationOutcome::Exited(status.code().unwrap_or(1)),
            Err(error) => {
                ElevationOutcome::Unavailable(format!("{what} could not be started: {error}"))
            }
        }
    }

    pub(super) fn run_elevated(
        program: &Path,
        args: &[OsString],
        terminal: bool,
    ) -> ElevationOutcome {
        if terminal
            && super::find_on_path("sudo", &std::env::var_os("PATH").unwrap_or_default()).is_some()
        {
            let status = Command::new("sudo")
                .arg("--")
                .arg(program)
                .args(args)
                .status();
            // `sudo` exits 1 both for a refused password and for a child that
            // exited 1; the child never exits 1 (it reports through its result
            // file and exits 0 or 2), so 1 is read as a refusal.
            return match exit_outcome(status, "sudo") {
                ElevationOutcome::Exited(1) => ElevationOutcome::Refused,
                other => other,
            };
        }
        if cfg!(target_os = "macos") {
            let command = std::iter::once(program.as_os_str().to_owned())
                .chain(args.iter().cloned())
                .map(|part| super::quote_posix_argument(&part.to_string_lossy()))
                .collect::<Vec<_>>()
                .join(" ");
            let output = Command::new("/usr/bin/osascript")
                .arg("-e")
                .arg(super::administrator_applescript(&command))
                .output();
            return match output {
                Ok(output) if output.status.success() => ElevationOutcome::Exited(0),
                // -128 is "User canceled." in every locale.
                Ok(output) if String::from_utf8_lossy(&output.stderr).contains("(-128)") => {
                    ElevationOutcome::Refused
                }
                Ok(output) => {
                    let detail = String::from_utf8_lossy(&output.stderr).trim().to_owned();
                    if detail.contains("(-60007)") || detail.contains("(-1743)") {
                        ElevationOutcome::Unavailable(format!(
                            "macOS could not show the administrator dialog here: {detail}"
                        ))
                    } else {
                        ElevationOutcome::Exited(output.status.code().unwrap_or(2))
                    }
                }
                Err(error) => ElevationOutcome::Unavailable(format!(
                    "osascript could not be started: {error}"
                )),
            };
        }
        ElevationOutcome::Unavailable(
            "no terminal to ask for a sudo password; run the command from a terminal".into(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_arguments_survive_the_command_line_round_trip() {
        for (argument, expected) in [
            ("plain", "plain"),
            ("", "\"\""),
            ("with space", "\"with space\""),
            ("C:\\Program Files\\x\\", "\"C:\\Program Files\\x\\\\\""),
            ("say \"hi\"", "\"say \\\"hi\\\"\""),
            ("a\\\"b", "\"a\\\\\\\"b\""),
            ("{\"k\":\"C:\\\\r m\"}", "\"{\\\"k\\\":\\\"C:\\\\r m\\\"}\""),
        ] {
            assert_eq!(
                crate::service::quote_argument(argument),
                expected,
                "{argument}"
            );
        }
    }

    #[test]
    fn posix_and_applescript_quoting_keep_hostile_characters_inert() {
        assert_eq!(quote_posix_argument("it's"), "'it'\\''s'");
        let script = administrator_applescript("'/a b/rm' 'x\"y' '\\'");
        assert_eq!(
            script,
            "do shell script \"'/a b/rm' 'x\\\"y' '\\\\'\" with administrator privileges"
        );
    }

    #[test]
    fn a_symlink_probe_leaves_nothing_behind() {
        let directory = tempfile::tempdir().unwrap();
        let _ = can_create_symlink(directory.path()).unwrap();
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn unix_accounts_can_always_create_symlinks() {
        let directory = tempfile::tempdir().unwrap();
        assert!(can_create_symlink(directory.path()).unwrap());
    }

    #[test]
    fn a_tool_is_found_on_path_and_a_path_like_name_never_is() {
        let directory = tempfile::tempdir().unwrap();
        let name = if cfg!(windows) {
            "rmtool.exe"
        } else {
            "rmtool"
        };
        let tool = directory.path().join(name);
        std::fs::write(&tool, b"").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let path = std::env::join_paths([directory.path()]).unwrap();
        assert_eq!(find_on_path("rmtool", &path), Some(tool));
        assert_eq!(find_on_path("absent-tool", &path), None);
        assert_eq!(find_on_path("../rmtool", &path), None);
    }

    /// Node.js on Windows ships a POSIX `npm` script beside `npm.cmd`; only the
    /// one Windows can start is an answer.
    #[cfg(windows)]
    #[test]
    fn an_extensionless_file_is_never_the_windows_answer() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join("npm"), b"#!/bin/sh\n").unwrap();
        let path = std::env::join_paths([directory.path()]).unwrap();
        assert_eq!(find_on_path("npm", &path), None);
        let cmd = directory.path().join("npm.cmd");
        std::fs::write(&cmd, b"@echo off\r\n").unwrap();
        assert_eq!(find_on_path("npm", &path), Some(cmd.clone()));
        assert_eq!(find_on_path("npm.cmd", &path), Some(cmd));
    }

    #[test]
    fn the_unfit_record_keeps_its_first_moment_and_clears() {
        let root = tempfile::tempdir().unwrap();
        let paths = AppPaths::rooted_at(root.path());
        paths.create_all().unwrap();
        assert_eq!(host_unfit(&paths).unwrap(), None);
        let first = Utc::now() - chrono::Duration::minutes(10);
        record_host_unfit(&paths, &["windows.symlink_privilege".into()], first).unwrap();
        let later = Utc::now();
        record_host_unfit(&paths, &["host.required_tools".into()], later).unwrap();
        let record = host_unfit(&paths).unwrap().unwrap();
        assert_eq!(record.since, first);
        assert_eq!(record.checked_at, later);
        assert_eq!(record.checks, ["host.required_tools"]);
        clear_host_unfit(&paths).unwrap();
        assert_eq!(host_unfit(&paths).unwrap(), None);
        clear_host_unfit(&paths).unwrap();
    }

    #[test]
    fn physical_memory_is_reported() {
        assert!(physical_memory_bytes().is_some_and(|bytes| bytes > 256 * 1024 * 1024));
    }

    #[test]
    fn a_directory_responds_and_a_not_yet_created_one_is_judged_by_its_parent() {
        let directory = tempfile::tempdir().unwrap();
        let deadline = std::time::Duration::from_secs(10);
        assert_eq!(
            directory_responds(directory.path(), deadline),
            Responsiveness::Responds
        );
        assert_eq!(
            directory_responds(&directory.path().join("not-yet").join("deeper"), deadline),
            Responsiveness::Responds
        );
        // Only this test's paths: the registry is shared with tests running
        // beside it.
        assert!(
            !PROBES_IN_FLIGHT
                .lock()
                .unwrap()
                .iter()
                .any(|path| path.starts_with(directory.path())),
            "a finished probe deregisters"
        );
    }

    /// While an earlier probe of a path is still blocked, a new one answers
    /// `Hung` at once instead of parking another thread on the same volume.
    #[test]
    fn a_path_still_being_probed_is_hung_without_a_second_thread() {
        let directory = tempfile::tempdir().unwrap();
        let stuck = directory.path().join("stuck-volume");
        PROBES_IN_FLIGHT.lock().unwrap().push(stuck.clone());
        let started = std::time::Instant::now();
        let answer = directory_responds(&stuck, std::time::Duration::from_secs(30));
        PROBES_IN_FLIGHT
            .lock()
            .unwrap()
            .retain(|path| *path != stuck);
        assert_eq!(answer, Responsiveness::Hung);
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
    }
}
