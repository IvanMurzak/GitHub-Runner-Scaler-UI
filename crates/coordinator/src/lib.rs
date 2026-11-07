//! The optional coordinator for `runner-manager` — stages 1 and 2.
//!
//! Receives GitHub `workflow_job` webhooks and wakes the connected, enrolled
//! hosts that serve the job's repository and labels, so they poll at once
//! instead of at their next interval. With a GitHub App configured it also
//! runs a reconciliation sweep ([`sweep`]) over the hosts' repositories, so a
//! lost webhook still wakes them and the hosts can poll GitHub rarely. The
//! coordinator advises; every host still computes its own demand and enforces
//! its own limits.
//!
//! Design: `.taskflow/2026-11-07-coordinator-server/README.md`. Deployment:
//! `docs/coordinator.md`.

pub mod github_app;
pub mod registry;
pub mod server;
pub mod store;
pub mod sweep;
pub mod webhook;
