// owner: b1-local-model-corpus
//
// ----------------------------------------------------------------------------
// A PURE MODEL OF THE LOCAL CLI, AND THE CORPUS OF CHAINS IT PREDICTS.
// ----------------------------------------------------------------------------
// `.taskflow/2026-09-10-cli-chains-acceptance/02-target-architecture.md` asks
// for hundreds of named, replayable CLI state transitions, each checked
// against an independent model. This directory is the model half: it never
// runs the binary and never imports production code. The runner that executes
// each typed action as a real `runner-manager` process and compares what it
// observes against these predictions is `cli_chains_acceptance.rs` (task b2);
// the model's own self-tests are `cli_chains_model.rs`.
//
// Both of those targets mount this directory with `mod cli_chains;`, so every
// item here is used by at least one of them and none of it is a test by
// itself: a `#[test]` placed in here would run once per mounting target.
//
// `dead_code` is allowed for the same reason `support/mod.rs` allows it: each
// integration-test target is its own crate, and a helper the runner uses is
// dead in the model-only target and the other way around.

#![allow(dead_code)]

pub mod action;
pub mod corpus;
pub mod coverage;
pub mod ids;
pub mod model;
pub mod transition;
pub mod values;
