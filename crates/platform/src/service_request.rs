//! Asking the running service to do something this process cannot.
//!
//! The service shares its state directory with the account that installed
//! it, so a request left there is a channel both sides can use with no
//! privilege and no socket. The asking command writes an identifier it chose
//! into the channel's request file; the service takes the request by deleting
//! the file, which is how the command knows somebody is listening; and the
//! service answers in the channel's result file under the same identifier,
//! which is how the command knows the answer is to this request.
//!
//! Two channels use it: [`CACHE_PRUNE`] and [`GITHUB_DISCOVERY`].

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

/// How often the service looks for a request.
pub const POLL: Duration = Duration::from_secs(2);

/// One request and its answer, as two files in the state directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Channel {
    request: &'static str,
    result: &'static str,
}

/// `host cache prune` for a cache root this account cannot write: the root of
/// a service running as another account (LocalSystem on Windows, root
/// elsewhere).
pub const CACHE_PRUNE: Channel = Channel {
    request: crate::dependency_cache::PRUNE_REQUEST_FILE,
    result: crate::dependency_cache::PRUNE_RESULT_FILE,
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
    request: "github-discovery.request",
    result: "github-discovery.result",
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

impl Channel {
    /// Where a request for the service lives.
    #[must_use]
    pub fn request_path(&self, state_dir: &Path) -> PathBuf {
        state_dir.join(self.request)
    }

    /// Takes a pending request, if there is one, and returns its identifier.
    /// Taking it is deleting it, so a request is answered once.
    #[must_use]
    pub fn take(&self, state_dir: &Path) -> Option<String> {
        let path = self.request_path(state_dir);
        let request = fs::read_to_string(&path).ok()?;
        fs::remove_file(&path).ok()?;
        Some(request.trim().to_owned())
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
        crate::host_fitness::write_atomically(&state_dir.join(self.result), &json)
    }

    /// The service's answer to `request`, once it has given one.
    #[must_use]
    pub fn read_answer<T: DeserializeOwned>(
        &self,
        state_dir: &Path,
        request: &str,
    ) -> Option<Result<T, String>> {
        fs::read(state_dir.join(self.result))
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
        let id = format!(
            "{}-{}",
            chrono::Utc::now().format("%Y%m%dT%H%M%S%.9fZ"),
            std::process::id()
        );
        let request = self.request_path(state_dir);
        crate::host_fitness::write_atomically(&request, id.as_bytes())
            .map_err(|error| AskError::NotSent(format!("{}: {error}", request.display())))?;
        sent();

        let started = Instant::now();
        while request.exists() {
            if started.elapsed() >= wait.taken {
                // Withdrawn, so a service that starts later does not answer a
                // command that is no longer waiting. Gone already means it was
                // taken after all.
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
                if let Some(request) = GITHUB_DISCOVERY.take(&state_dir) {
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
        assert!(!GITHUB_DISCOVERY.request_path(dir.path()).exists());
        assert_eq!(GITHUB_DISCOVERY.take(dir.path()), None, "answered once");
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
            !GITHUB_DISCOVERY.request_path(dir.path()).exists(),
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
            while GITHUB_DISCOVERY.take(&state_dir).is_none() {
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
}
