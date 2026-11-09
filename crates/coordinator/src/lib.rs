//! The optional coordinator for `runner-manager` — stages 1 to 4.
//!
//! Receives GitHub `workflow_job` webhooks and wakes the connected, enrolled
//! hosts that serve the job's repository and labels, so they poll at once
//! instead of at their next interval. With a GitHub App configured it also
//! runs a reconciliation sweep ([`sweep`]) over the hosts' repositories, so a
//! lost webhook still wakes them and the hosts can poll GitHub rarely. The
//! coordinator advises; every host still computes its own demand and enforces
//! its own limits. Stage 3 adds [`placement`]: a queued job that asks for a
//! shared pool label is started by exactly one host the coordinator picks.
//! Stage 4 adds [`stats`]: what each job used, per host, and a placement that
//! weighs a queue's heaviest job against each host's free memory, warm
//! workspace and history.
//!
//! Design: `.taskflow/2026-11-07-coordinator-server/README.md`. Deployment:
//! `docs/coordinator.md`.

/// The clock placement and statistics read.
///
/// Tokio's, as a [`std::time::Instant`]: the system's in service, and a virtual
/// one under `tokio::time::pause()`, which is what lets the balance simulation
/// (`tests/balance_sim.rs`) run hours of placement in a moment.
pub(crate) mod clock {
    #[must_use]
    pub fn now() -> std::time::Instant {
        tokio::time::Instant::now().into_std()
    }
}

pub mod github_app;
pub mod placement;
pub mod registry;
pub mod server;
pub mod stats;
pub mod store;
pub mod sweep;
pub mod webhook;
