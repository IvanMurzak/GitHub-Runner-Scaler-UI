//! Commands a person signed in to the coordinator runs on a host (protocol
//! version 5): the coordinator relays `runner-manager` arguments to the host,
//! and the host decides what it runs. A read is always answered; a change
//! only by a host whose operator allowed changes through the coordinator.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use runner_manager_domain::coordinator_protocol::{CommandResult, RunCommand, ServerMessage};
use tokio::sync::oneshot;

use crate::registry::Registry;

/// How long a command may take on the host: `repo add` asks GitHub.
pub const COMMAND_TIMEOUT: Duration = Duration::from_secs(60);

/// Why a command did not run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RemoteError {
    #[error("the host is not connected")]
    Offline,
    #[error("the host runs a runner-manager too old to take commands (before 0.4.61)")]
    TooOld,
    #[error("the command is too long, or has a control character in it")]
    Malformed,
    #[error("the host did not answer in time")]
    Timeout,
}

impl RemoteError {
    /// The word the record keeps for it.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Offline => "offline",
            Self::TooOld => "too_old",
            Self::Malformed => "malformed",
            Self::Timeout => "timeout",
        }
    }

    /// The HTTP status it answers with.
    #[must_use]
    pub const fn status(self) -> axum::http::StatusCode {
        use axum::http::StatusCode;
        match self {
            Self::Offline => StatusCode::SERVICE_UNAVAILABLE,
            Self::TooOld => StatusCode::CONFLICT,
            Self::Malformed => StatusCode::BAD_REQUEST,
            Self::Timeout => StatusCode::GATEWAY_TIMEOUT,
        }
    }
}

/// A command sent and not yet answered: the connection it went out on, and
/// who waits for its result.
#[derive(Debug)]
struct Pending {
    host_id: String,
    connection: u64,
    sender: oneshot::Sender<CommandResult>,
}

/// The commands sent and not yet answered, by request id.
#[derive(Debug, Default)]
pub struct RemoteCommands {
    pending: Mutex<HashMap<String, Pending>>,
}

impl RemoteCommands {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Pending>> {
        self.pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Runs `argv` on `host_id` for `by`, and waits for its result.
    ///
    /// # Errors
    /// [`RemoteError`].
    pub async fn run(
        &self,
        registry: &Registry,
        host_id: &str,
        argv: Vec<String>,
        by: &str,
        timeout: Duration,
    ) -> Result<CommandResult, RemoteError> {
        let Some((connection, version)) = registry.link(host_id) else {
            return Err(RemoteError::Offline);
        };
        if version < runner_manager_domain::coordinator_protocol::COMMAND_VERSION {
            return Err(RemoteError::TooOld);
        }
        let command = RunCommand {
            request_id: hex::encode(rand::random::<[u8; 16]>()),
            argv,
            by: by.to_owned(),
        };
        if !command.well_formed() {
            return Err(RemoteError::Malformed);
        }
        let (sender, receiver) = oneshot::channel();
        let id = command.request_id.clone();
        self.lock().insert(
            id.clone(),
            Pending {
                host_id: host_id.to_owned(),
                connection,
                sender,
            },
        );
        if !registry.send(host_id, ServerMessage::RunCommand(command)) {
            self.lock().remove(&id);
            return Err(RemoteError::Offline);
        }
        let outcome = tokio::time::timeout(timeout, receiver).await;
        self.lock().remove(&id);
        match outcome {
            Ok(Ok(result)) => Ok(result),
            // The host went away: `connection_gone` dropped the sender.
            Ok(Err(_)) => Err(RemoteError::Offline),
            Err(_) => Err(RemoteError::Timeout),
        }
    }

    /// `host_id` answered. A result nobody waits for (it timed out), or one
    /// for a command sent to another host, is dropped.
    pub fn complete(&self, host_id: &str, result: CommandResult) {
        let mut pending = self.lock();
        if pending
            .get(&result.request_id)
            .is_some_and(|waiting| waiting.host_id == host_id)
            && let Some(waiting) = pending.remove(&result.request_id)
        {
            let _ = waiting.sender.send(result);
        }
    }

    /// `host_id`'s `connection` ended: the commands sent on it will never be
    /// answered, and their callers learn so at once instead of timing out.
    pub fn connection_gone(&self, host_id: &str, connection: u64) {
        self.lock()
            .retain(|_, waiting| waiting.host_id != host_id || waiting.connection != connection);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_command_for_a_host_that_is_not_connected_is_refused_at_once() {
        let remote = RemoteCommands::default();
        let registry = Registry::default();
        assert_eq!(
            remote
                .run(
                    &registry,
                    "nobody",
                    vec!["repo".into()],
                    "me",
                    COMMAND_TIMEOUT
                )
                .await,
            Err(RemoteError::Offline)
        );
        // An answer nobody waits for changes nothing.
        remote.complete(
            "nobody",
            CommandResult {
                request_id: "x".into(),
                exit_code: 0,
                stdout: String::new(),
                stderr: String::new(),
                truncated: false,
                access: None,
            },
        );
    }
}
