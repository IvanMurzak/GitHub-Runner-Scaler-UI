// owner: b2-local-chain-runner
//
// ----------------------------------------------------------------------------
// THE RUNNER HALF OF THE LOCAL CLI CHAINS: REAL PROCESSES, JUDGED BY THE MODEL.
// ----------------------------------------------------------------------------
// `cli_chains/` (task b1) is a pure model of the local CLI and a corpus of
// typed chains. This directory is what executes those chains against the real
// `runner-manager` binary, one fresh process per action, and compares every
// transition against the model's prediction:
//
// * `scenario` owns one case's isolation: a temporary directory holding the
//   `--data-dir`, the scratch `<roots>` and the child's working directory, a
//   loopback fake GitHub, a service fixture tag nobody else uses, and the
//   in-process seeding of states only a daemon could otherwise reach;
// * `observe` reads back what a step left behind through public interfaces
//   only -- the `Store` trait, the rooted secret store, the filesystem, and the
//   fake GitHub's request log -- and rebuilds it into the model's own shape;
// * `oracle` compares expectation and observation plane by plane (exit, output,
//   store, filesystem, requests) and names every divergence;
// * `run` drives a case step by step and stops at the first divergence;
// * `report` renders that divergence with everything needed to replay it;
// * `selection` decides which cases the default run executes, and how one case
//   is selected for local diagnosis without the default run ever omitting one;
// * `confinement` proves the product never reached the developer's standard
//   application-data locations or the product's own service identity.
//
// It lives beside `cli_chains/` rather than inside it on purpose: the model
// directory is forbidden, by `cli_chains_model.rs`, from naming a production
// crate or starting a process, and this directory does both.
//
// `dead_code` is allowed for the reason `support/mod.rs` gives: every
// integration-test target is its own crate and not every helper is used by
// every target that might mount this one.

#![allow(dead_code)]

pub mod confinement;
pub mod observe;
pub mod oracle;
pub mod report;
pub mod run;
pub mod scenario;
pub mod selection;
