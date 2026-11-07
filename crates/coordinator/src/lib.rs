//! The optional coordinator for `runner-manager` — stage 1.
//!
//! Receives GitHub `workflow_job` webhooks and wakes the connected, enrolled
//! hosts that serve the job's repository and labels, so they poll at once
//! instead of at their next interval. The coordinator advises; every host
//! still computes its own demand and enforces its own limits.
//!
//! Design: `.taskflow/2026-11-07-coordinator-server/README.md`. Deployment:
//! `docs/coordinator.md`.

pub mod registry;
pub mod server;
pub mod store;
pub mod webhook;
