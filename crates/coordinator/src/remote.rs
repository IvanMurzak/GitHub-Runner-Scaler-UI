//! Commands a person signed in to the coordinator runs on a host (protocol
//! version 5): the coordinator relays `runner-manager` arguments to the host,
//! and the host decides what it runs. A read is always answered; a change
//! only by a host whose operator allowed changes through the coordinator.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use runner_manager_domain::coordinator_protocol::{
    COMMAND_VERSION, CommandResult, RunCommand, ServerMessage,
};
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

/// The commands sent and not yet answered.
#[derive(Debug, Default)]
pub struct RemoteCommands {
    pending: Mutex<HashMap<String, oneshot::Sender<CommandResult>>>,
}

impl RemoteCommands {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, oneshot::Sender<CommandResult>>> {
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
        match registry.protocol_version(host_id) {
            None => return Err(RemoteError::Offline),
            Some(version) if version < COMMAND_VERSION => return Err(RemoteError::TooOld),
            Some(_) => {}
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
        self.lock().insert(id.clone(), sender);
        if !registry.send(host_id, ServerMessage::RunCommand(command)) {
            self.lock().remove(&id);
            return Err(RemoteError::Offline);
        }
        let outcome = tokio::time::timeout(timeout, receiver).await;
        self.lock().remove(&id);
        match outcome {
            Ok(Ok(result)) => Ok(result),
            // The host went away: its connection's sender was dropped.
            Ok(Err(_)) => Err(RemoteError::Offline),
            Err(_) => Err(RemoteError::Timeout),
        }
    }

    /// A host answered. A result nobody waits for (it timed out) is dropped.
    pub fn complete(&self, result: CommandResult) {
        if let Some(sender) = self.lock().remove(&result.request_id) {
            let _ = sender.send(result);
        }
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
        remote.complete(CommandResult {
            request_id: "x".into(),
            exit_code: 0,
            stdout: String::new(),
            stderr: String::new(),
            truncated: false,
        });
    }
}
