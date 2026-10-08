//! Asking the running service to do something this process cannot.
//!
//! The service shares its state directory with the account that installed
//! it, so a request left there is a channel both sides can use with no
//! privilege and no socket. The asking command leaves a request under an
//! identifier it chose; the service takes the request by deleting it, which is
//! how the command knows somebody is listening; and the service answers under
//! the same identifier, which is how the command knows the answer is to this
//! request.
//!
//! [`GITHUB_DISCOVERY`] gives every request its own pair of files under
//! `service-requests/`, so commands asking at once do not displace each other.
//! [`CACHE_PRUNE`] keeps the single pair of files it was introduced with, which
//! a service from that release still reads.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

/// How often the service looks for a request.
pub const POLL: Duration = Duration::from_secs(2);

/// The directory under the state directory per-request channels use.
const REQUESTS_DIR: &str = "service-requests";

/// One kind of request and its answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Channel {
    slots: Slots,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Slots {
    /// One request file and one result file, shared by every asker.
    One {
        request: &'static str,
        result: &'static str,
    },
    /// `<prefix>.<id>.request` and `<prefix>.<id>.result` per request.
    PerRequest(&'static str),
}

/// `host cache prune` for a cache root this account cannot write: the root of
/// a service running as another account (LocalSystem on Windows, root
/// elsewhere).
pub const CACHE_PRUNE: Channel = Channel {
    slots: Slots::One {
        request: crate::dependency_cache::PRUNE_REQUEST_FILE,
        result: crate::dependency_cache::PRUNE_RESULT_FILE,
    },
};

/// What the stored GitHub credential reaches, asked of the service by a
/// command that cannot read the credential itself.
///
/// The reason is a login-mode Mac reached over SSH: the credential is in the
/// login keychain, which an SSH session cannot unlock, while the service runs
/// in the desktop session and reads it every poll. `repo add`, `org add` and
/// `auth status` used to fail there with the keychain's error. The answer
/// holds what GitHub said about the installations, never the credential.
pub const GITHUB_DISCOVERY: Channel = Channel {
    slots: Slots::PerRequest("github-discovery"),
};

/// How long a command waits on the service, and how often it looks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Wait {
    /// For the service to take the request: several of its polls, so a
    /// running service always answers inside it.
    pub taken: Duration,
    /// For the answer, once the service has taken the request.
    pub finished: Duration,
    pub poll: Duration,
}

impl Wait {
    /// What a command waiting on a GitHub request uses.
    pub const GITHUB: Self = Self {
        taken: Duration::from_secs(4 * POLL.as_secs()),
        finished: Duration::from_secs(90),
        poll: Duration::from_millis(250),
    };
}

/// Why a command got no answer.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AskError {
    #[error("the request could not be left for the service: {0}")]
    NotSent(String),
    #[error("no running service took the request within {0} seconds")]
    NotTaken(u64),
    #[error("the service took the request but gave no answer within {0} seconds")]
    NoAnswer(u64),
    #[error("the service could not answer: {0}")]
    Refused(String),
}

#[derive(Debug, Serialize, Deserialize)]
struct Answer<T> {
    request: String,
    outcome: Result<T, String>,
}

/// The longest request identifier taken, and the characters it may hold. An
/// identifier is chosen by the asking command (a timestamp and a process id)
/// and copied into the answer, so the service takes nothing else.
const MAX_ID: usize = 64;

fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_ID
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_'))
}

/// An answer nobody collected is removed after this long.
const UNCOLLECTED: Duration = Duration::from_secs(10 * 60);

/// Reads a single-slot request without following a link and without reading
/// more than an identifier's worth.
///
/// The service may run as root or LocalSystem while the state directory
/// belongs to the account that installed it, so the request path is under that
/// account's control. Following a link there would have the service read a
/// file of the link's choosing, and copy it into an answer that account can
/// read; a FIFO or `/dev/zero` would hold the service's loop.
fn read_request(path: &Path) -> Option<String> {
    use std::io::Read as _;
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::custom_flags(
        &mut options,
        libc::O_NOFOLLOW | libc::O_NONBLOCK,
    );
    #[cfg(windows)]
    std::os::windows::fs::OpenOptionsExt::custom_flags(
        &mut options,
        // FILE_FLAG_OPEN_REPARSE_POINT: open a link as itself.
        0x0020_0000,
    );
    let file = options.open(path).ok()?;
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    let mut text = String::new();
    file.take(MAX_ID as u64 + 2)
        .read_to_string(&mut text)
        .ok()?;
    let id = text.trim();
    valid_id(id).then(|| id.to_owned())
}

/// The answer file is the service's to write and the asking account's to read,
/// whichever account the service runs as. It holds no secret.
fn readable_by_the_asker(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o644))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

impl Channel {
    /// Where a single-slot channel's request lives.
    #[must_use]
    pub fn request_path(&self, state_dir: &Path) -> PathBuf {
        match self.slots {
            Slots::One { request, .. } => state_dir.join(request),
            Slots::PerRequest(prefix) => state_dir.join(REQUESTS_DIR).join(prefix),
        }
    }

    fn request_file(&self, state_dir: &Path, id: &str) -> PathBuf {
        match self.slots {
            Slots::One { request, .. } => state_dir.join(request),
            Slots::PerRequest(prefix) => state_dir
                .join(REQUESTS_DIR)
                .join(format!("{prefix}.{id}.request")),
        }
    }

    fn result_file(&self, state_dir: &Path, id: &str) -> PathBuf {
        match self.slots {
            Slots::One { result, .. } => state_dir.join(result),
            Slots::PerRequest(prefix) => state_dir
                .join(REQUESTS_DIR)
                .join(format!("{prefix}.{id}.result")),
        }
    }

    /// Takes the pending requests and returns their identifiers. Taking one is
    /// deleting it, so a request is answered once.
    #[must_use]
    pub fn take(&self, state_dir: &Path) -> Vec<String> {
        match self.slots {
            Slots::One { request, .. } => {
                let path = state_dir.join(request);
                if fs::symlink_metadata(&path).is_err() {
                    return Vec::new();
                }
                let id = read_request(&path);
                // Removed whatever it held: an unreadable or malformed request
                // is not going to become a good one.
                if fs::remove_file(&path).is_err() {
                    return Vec::new();
                }
                id.into_iter().collect()
            }
            Slots::PerRequest(prefix) => {
                let Ok(entries) = fs::read_dir(state_dir.join(REQUESTS_DIR)) else {
                    return Vec::new();
                };
                let mut taken = Vec::new();
                for entry in entries.flatten() {
                    let name = entry.file_name();
                    let Some(name) = name.to_str() else { continue };
                    let Some(rest) = name.strip_prefix(prefix).and_then(|r| r.strip_prefix('.'))
                    else {
                        continue;
                    };
                    if let Some(id) = rest.strip_suffix(".request") {
                        // The identifier is the file's name, so its contents
                        // are never read, and a link is removed as a link.
                        if fs::remove_file(entry.path()).is_ok() && valid_id(id) {
                            taken.push(id.to_owned());
                        }
                    } else if rest.ends_with(".result")
                        && entry
                            .metadata()
                            .and_then(|meta| meta.modified())
                            .ok()
                            .and_then(|at| at.elapsed().ok())
                            .is_some_and(|age| age >= UNCOLLECTED)
                    {
                        let _ = fs::remove_file(entry.path());
                    }
                }
                taken
            }
        }
    }

    /// The service's answer to `request`.
    ///
    /// # Errors
    /// The answer could not be encoded or written.
    pub fn answer<T: Serialize>(
        &self,
        state_dir: &Path,
        request: &str,
        outcome: Result<T, String>,
    ) -> io::Result<()> {
        let answer = Answer {
            request: request.to_owned(),
            outcome,
        };
        let json = serde_json::to_vec_pretty(&answer).map_err(io::Error::other)?;
        let path = self.result_file(state_dir, request);
        crate::host_fitness::write_atomically(&path, &json)?;
        readable_by_the_asker(&path)
    }

    /// The service's answer to `request`, once it has given one.
    #[must_use]
    pub fn read_answer<T: DeserializeOwned>(
        &self,
        state_dir: &Path,
        request: &str,
    ) -> Option<Result<T, String>> {
        fs::read(self.result_file(state_dir, request))
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Answer<T>>(&bytes).ok())
            .filter(|answer| answer.request == request)
            .map(|answer| answer.outcome)
    }

    /// Asks the service and waits for its answer.
    ///
    /// # Errors
    /// [`AskError`], naming which half of the exchange did not happen.
    pub fn ask<T: DeserializeOwned>(&self, state_dir: &Path, wait: Wait) -> Result<T, AskError> {
        self.ask_with(state_dir, wait, || {})
    }

    /// [`Self::ask`], calling `sent` once the request is in place, so the
    /// command can say it is waiting.
    ///
    /// # Errors
    /// As [`Self::ask`].
    pub fn ask_with<T: DeserializeOwned>(
        &self,
        state_dir: &Path,
        wait: Wait,
        sent: impl FnOnce(),
    ) -> Result<T, AskError> {
        // Unique within this process as well as across processes: two threads
        // can read the same instant where the clock is coarse (macOS).
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = format!(
            "{}-{}-{}",
            chrono::Utc::now().format("%Y%m%dT%H%M%S%.9fZ"),
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        );
        let request = self.request_file(state_dir, &id);
        crate::host_fitness::write_atomically(&request, id.as_bytes())
            .map_err(|error| AskError::NotSent(format!("{}: {error}", request.display())))?;
        sent();

        let started = Instant::now();
        let pending = |request: &Path| match self.slots {
            Slots::One { .. } => read_request(request).as_deref() == Some(id.as_str()),
            Slots::PerRequest(_) => fs::symlink_metadata(request).is_ok(),
        };
        while pending(&request) {
            if started.elapsed() >= wait.taken {
                // Withdrawn, so a service that starts later does not answer a
                // command that is no longer waiting: only this command's own
                // request, which in a single slot another command may have
                // replaced. Gone already means it was taken after all.
                match fs::remove_file(&request) {
                    Err(error) if error.kind() == io::ErrorKind::NotFound => break,
                    _ => return Err(AskError::NotTaken(wait.taken.as_secs())),
                }
            }
            std::thread::sleep(wait.poll);
        }

        let taken = Instant::now();
        loop {
            if let Some(outcome) = self.read_answer(state_dir, &id) {
                if matches!(self.slots, Slots::PerRequest(_)) {
                    let _ = fs::remove_file(self.result_file(state_dir, &id));
                }
                return outcome.map_err(AskError::Refused);
            }
            if taken.elapsed() >= wait.finished {
                return Err(AskError::NoAnswer(wait.finished.as_secs()));
            }
            std::thread::sleep(wait.poll);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const QUICK: Wait = Wait {
        taken: Duration::from_millis(600),
        finished: Duration::from_secs(5),
        poll: Duration::from_millis(20),
    };

    /// A stand-in service: takes one request and answers it with `outcome`.
    fn service(
        state_dir: PathBuf,
        outcome: Result<u32, String>,
    ) -> std::thread::JoinHandle<String> {
        std::thread::spawn(move || {
            loop {
                if let Some(request) = GITHUB_DISCOVERY.take(&state_dir).pop() {
                    GITHUB_DISCOVERY
                        .answer(&state_dir, &request, outcome)
                        .unwrap();
                    return request;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        })
    }

    #[test]
    fn a_running_service_takes_the_request_once_and_answers_it() {
        let dir = tempfile::tempdir().unwrap();
        let answering = service(dir.path().to_path_buf(), Ok(7));
        assert_eq!(GITHUB_DISCOVERY.ask::<u32>(dir.path(), QUICK), Ok(7));
        answering.join().unwrap();
        assert!(
            GITHUB_DISCOVERY.take(dir.path()).is_empty(),
            "answered once"
        );
    }

    #[test]
    fn a_service_that_cannot_answer_says_why() {
        let dir = tempfile::tempdir().unwrap();
        let answering = service(dir.path().to_path_buf(), Err("no credential".into()));
        assert_eq!(
            GITHUB_DISCOVERY.ask::<u32>(dir.path(), QUICK),
            Err(AskError::Refused("no credential".into()))
        );
        answering.join().unwrap();
    }

    #[test]
    fn with_no_service_listening_the_request_is_withdrawn() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            GITHUB_DISCOVERY.ask::<u32>(dir.path(), QUICK),
            Err(AskError::NotTaken(_))
        ));
        assert!(
            GITHUB_DISCOVERY.take(dir.path()).is_empty(),
            "a later service must not answer a command that stopped waiting"
        );
    }

    #[test]
    fn an_answer_to_another_request_is_not_taken_for_this_one() {
        let dir = tempfile::tempdir().unwrap();
        GITHUB_DISCOVERY
            .answer(dir.path(), "an-earlier-request", Ok(1_u32))
            .unwrap();
        let state_dir = dir.path().to_path_buf();
        // Takes the request and never answers it.
        let silent = std::thread::spawn(move || {
            while GITHUB_DISCOVERY.take(&state_dir).is_empty() {
                std::thread::sleep(Duration::from_millis(10));
            }
        });
        let wait = Wait {
            finished: Duration::from_millis(300),
            ..QUICK
        };
        assert!(matches!(
            GITHUB_DISCOVERY.ask::<u32>(dir.path(), wait),
            Err(AskError::NoAnswer(_))
        ));
        silent.join().unwrap();
    }

    /// Two commands asking at once each get their own answer: neither
    /// replaces the other's request.
    #[test]
    fn commands_asking_at_once_each_get_their_own_answer() {
        let dir = tempfile::tempdir().unwrap();
        let state_dir = dir.path().to_path_buf();
        let service = std::thread::spawn(move || {
            let mut answered = 0;
            let deadline = Instant::now() + Duration::from_secs(10);
            while answered < 2 && Instant::now() < deadline {
                for request in GITHUB_DISCOVERY.take(&state_dir) {
                    GITHUB_DISCOVERY
                        .answer(&state_dir, &request, Ok(request.len()))
                        .unwrap();
                    answered += 1;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            answered
        });
        let asking =
            |dir: PathBuf| std::thread::spawn(move || GITHUB_DISCOVERY.ask::<usize>(&dir, QUICK));
        let first = asking(dir.path().to_path_buf());
        let second = asking(dir.path().to_path_buf());
        assert!(first.join().unwrap().is_ok());
        assert!(second.join().unwrap().is_ok());
        assert_eq!(service.join().unwrap(), 2);
    }

    /// The service never follows a link left at a request path, and never
    /// takes an identifier it would not have chosen.
    #[cfg(unix)]
    #[test]
    fn a_request_that_is_a_link_or_not_an_identifier_is_dropped_unread() {
        let dir = tempfile::tempdir().unwrap();
        let secret = dir.path().join("only-the-service-may-read");
        fs::write(&secret, "the contents of somebody else's file").unwrap();
        let request = CACHE_PRUNE.request_path(dir.path());
        std::os::unix::fs::symlink(&secret, &request).unwrap();
        assert!(CACHE_PRUNE.take(dir.path()).is_empty());
        assert!(
            fs::symlink_metadata(&request).is_err(),
            "the link is removed"
        );
        assert!(secret.exists(), "and only the link");

        fs::write(&request, "not an identifier\nat all").unwrap();
        assert!(CACHE_PRUNE.take(dir.path()).is_empty());
        fs::write(&request, "20261007T221210.123456789Z-4242\n").unwrap();
        assert_eq!(
            CACHE_PRUNE.take(dir.path()),
            ["20261007T221210.123456789Z-4242"]
        );
    }
}
