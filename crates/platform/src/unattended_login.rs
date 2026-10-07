//! Whether this Mac comes back to work by itself after an unattended restart.
//!
//! A login-mode service is a LaunchAgent: it runs only once its account has
//! signed in. Automatic login signs that account in at boot, so the service
//! does come back, and `service status` used to say it would not on every
//! login-mode host, automatic login or not. FileVault defeats automatic login
//! (the Mac waits at the unlock screen after a restart) and holds back a boot
//! service too, because nothing on the data volume starts before it is
//! unlocked.
//!
//! This module only reports. Automatic login and FileVault are security
//! settings and nothing here changes either of them; [`AUTO_LOGIN_STEPS`] and
//! [`FILEVAULT_STEPS`] are what an operator is told to do instead.

use runner_manager_domain::model::StartMode;

/// Where macOS records the automatic-login account. World-readable; the
/// password beside it (`/etc/kcpassword`) is not, and is not read.
pub const LOGINWINDOW_PREFERENCES: &str = "/Library/Preferences/com.apple.loginwindow";

/// The System Settings steps that turn automatic login on.
pub const AUTO_LOGIN_STEPS: &str = "System Settings > Users & Groups > \"Automatically log in \
                                    as\", choose the account the service runs as, and enter its \
                                    password";

/// The System Settings steps that turn FileVault off.
pub const FILEVAULT_STEPS: &str = "System Settings > Privacy & Security > FileVault > \"Turn \
                                   Off…\" (macOS turns automatic login off while FileVault is \
                                   on)";

/// The automatic-login setting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AutoLogin {
    Off,
    As(String),
    Unknown(String),
}

/// What a probe of this Mac found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnattendedLogin {
    pub auto_login: AutoLogin,
    /// `None` when `fdesetup` gave no answer this module understands.
    pub filevault_on: Option<bool>,
}

/// Whether a service in `mode`, running as `account`, comes back after an
/// unattended restart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resume {
    /// It does.
    Resumes,
    /// FileVault holds the Mac at its unlock screen.
    FileVaultOn,
    /// Nobody is signed in automatically.
    NoAutomaticLogin,
    /// Somebody else is: the service's account still has to sign in.
    AutomaticLoginAsAnother(String),
    /// Not known; the reason says why.
    Unknown(String),
}

impl Resume {
    /// What `service status` says about it, in full sentences, with the steps
    /// that change it. `None` when the service resumes.
    #[must_use]
    pub fn explain(&self, account: &str) -> Option<String> {
        const GAP: &str = "This host does not resume work after an unattended reboot";
        match self {
            Self::Resumes => None,
            Self::FileVaultOn => Some(format!(
                "{GAP}: FileVault is on, so after a restart the Mac waits at its unlock screen \
                 until somebody types a password, and the service does not start until then. To \
                 have it come back by itself: {FILEVAULT_STEPS}."
            )),
            Self::NoAutomaticLogin => Some(format!(
                "{GAP}: automatic login is off, so after a restart this login-mode service waits \
                 for {account} to sign in. To have it come back by itself: {AUTO_LOGIN_STEPS}; or \
                 install the service to start at boot (`sudo runner-manager service install \
                 --start-at boot`)."
            )),
            Self::AutomaticLoginAsAnother(other) => Some(format!(
                "{GAP}: automatic login signs in {other}, not {account}, so after a restart this \
                 login-mode service waits for {account} to sign in. To change it: \
                 {AUTO_LOGIN_STEPS}."
            )),
            Self::Unknown(why) => Some(format!(
                "Whether this host resumes work after an unattended reboot could not be read: \
                 {why}."
            )),
        }
    }
}

/// Judges what was found for a service in `mode` running as `account`.
#[must_use]
pub fn resume(found: &UnattendedLogin, mode: StartMode, account: &str) -> Resume {
    match found.filevault_on {
        Some(true) => return Resume::FileVaultOn,
        Some(false) => {}
        None => return Resume::Unknown("`fdesetup status` gave no answer".into()),
    }
    if mode == StartMode::Boot {
        return Resume::Resumes;
    }
    match &found.auto_login {
        AutoLogin::Off => Resume::NoAutomaticLogin,
        AutoLogin::As(user) if user == account => Resume::Resumes,
        AutoLogin::As(user) => Resume::AutomaticLoginAsAnother(user.clone()),
        AutoLogin::Unknown(why) => Resume::Unknown(why.clone()),
    }
}

/// Reads `fdesetup status`. FileVault counts as on while it is turning on or
/// off, because the unlock screen is there until decryption finishes.
#[must_use]
pub fn parse_filevault_status(output: &str) -> Option<bool> {
    let output = output.trim();
    if output.starts_with("FileVault is Off") {
        Some(false)
    } else if output.starts_with("FileVault is On")
        || output.contains("Encryption in progress")
        || output.contains("Decryption in progress")
    {
        Some(true)
    } else {
        None
    }
}

/// Reads `defaults read <loginwindow> autoLoginUser`: its exit status, its
/// standard output and its standard error.
#[must_use]
pub fn parse_auto_login(success: bool, stdout: &str, stderr: &str) -> AutoLogin {
    let user = stdout.trim();
    if success && !user.is_empty() {
        AutoLogin::As(user.to_owned())
    } else if stderr.contains("does not exist") {
        AutoLogin::Off
    } else {
        AutoLogin::Unknown(format!("`defaults read` failed: {}", stderr.trim()))
    }
}

/// Probes this Mac. `None` on every other platform.
#[must_use]
pub fn probe() -> Option<UnattendedLogin> {
    #[cfg(target_os = "macos")]
    {
        let auto_login = match std::process::Command::new("/usr/bin/defaults")
            .args(["read", LOGINWINDOW_PREFERENCES, "autoLoginUser"])
            .output()
        {
            Ok(output) => parse_auto_login(
                output.status.success(),
                &String::from_utf8_lossy(&output.stdout),
                &String::from_utf8_lossy(&output.stderr),
            ),
            Err(error) => AutoLogin::Unknown(format!("/usr/bin/defaults: {error}")),
        };
        let filevault_on = std::process::Command::new("/usr/bin/fdesetup")
            .arg("status")
            .output()
            .ok()
            .and_then(|output| parse_filevault_status(&String::from_utf8_lossy(&output.stdout)));
        Some(UnattendedLogin {
            auto_login,
            filevault_on,
        })
    }
    #[cfg(not(target_os = "macos"))]
    {
        None
    }
}

/// The name of the account this process runs as, from `id -un`.
#[must_use]
pub fn current_account() -> Option<String> {
    #[cfg(unix)]
    {
        let output = std::process::Command::new("/usr/bin/id")
            .arg("-un")
            .output()
            .ok()?;
        let name = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        (output.status.success() && !name.is_empty()).then_some(name)
    }
    #[cfg(not(unix))]
    {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn found(auto_login: AutoLogin, filevault_on: Option<bool>) -> UnattendedLogin {
        UnattendedLogin {
            auto_login,
            filevault_on,
        }
    }

    #[test]
    fn automatic_login_as_the_service_account_brings_a_login_service_back() {
        let ivan = found(AutoLogin::As("ivan".into()), Some(false));
        assert_eq!(resume(&ivan, StartMode::Login, "ivan"), Resume::Resumes);
        assert_eq!(Resume::Resumes.explain("ivan"), None);
    }

    #[test]
    fn a_login_service_without_automatic_login_waits_for_a_sign_in() {
        let off = found(AutoLogin::Off, Some(false));
        let verdict = resume(&off, StartMode::Login, "ivan");
        assert_eq!(verdict, Resume::NoAutomaticLogin);
        let said = verdict.explain("ivan").unwrap();
        assert!(said.contains(AUTO_LOGIN_STEPS), "{said}");

        let other = found(AutoLogin::As("kiosk".into()), Some(false));
        assert_eq!(
            resume(&other, StartMode::Login, "ivan"),
            Resume::AutomaticLoginAsAnother("kiosk".into())
        );
    }

    #[test]
    fn filevault_holds_back_both_start_modes_and_automatic_login_does_not_help() {
        let locked = found(AutoLogin::As("ivan".into()), Some(true));
        for mode in [StartMode::Login, StartMode::Boot] {
            let verdict = resume(&locked, mode, "ivan");
            assert_eq!(verdict, Resume::FileVaultOn, "{mode}");
            assert!(verdict.explain("ivan").unwrap().contains(FILEVAULT_STEPS));
        }
        // A boot service needs no sign-in once FileVault is off.
        let off = found(AutoLogin::Off, Some(false));
        assert_eq!(resume(&off, StartMode::Boot, "root"), Resume::Resumes);
    }

    #[test]
    fn an_unanswered_probe_is_unknown_and_never_a_verdict() {
        let unread = found(AutoLogin::As("ivan".into()), None);
        assert!(matches!(
            resume(&unread, StartMode::Login, "ivan"),
            Resume::Unknown(_)
        ));
        let unreadable = found(AutoLogin::Unknown("no".into()), Some(false));
        assert!(matches!(
            resume(&unreadable, StartMode::Login, "ivan"),
            Resume::Unknown(_)
        ));
    }

    #[test]
    fn the_probe_outputs_are_read_as_macos_writes_them() {
        assert_eq!(parse_filevault_status("FileVault is Off.\n"), Some(false));
        assert_eq!(parse_filevault_status("FileVault is On.\n"), Some(true));
        assert_eq!(
            parse_filevault_status("Encryption in progress: Percent completed = 12.0\n"),
            Some(true)
        );
        assert_eq!(parse_filevault_status(""), None);

        assert_eq!(
            parse_auto_login(true, "ivan\n", ""),
            AutoLogin::As("ivan".into())
        );
        assert_eq!(
            parse_auto_login(
                false,
                "",
                "The domain/default pair of (/Library/Preferences/com.apple.loginwindow, \
                 autoLoginUser) does not exist\n"
            ),
            AutoLogin::Off
        );
        assert!(matches!(
            parse_auto_login(false, "", "Operation not permitted"),
            AutoLogin::Unknown(_)
        ));
    }
}
