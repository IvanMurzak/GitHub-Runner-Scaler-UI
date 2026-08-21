// owner: b1-domain-core
//
// b1 owns `clock` and `fixtures`; group C owns `github` (c3 creates the fake
// gateway, c4 extends it).

//! Test doubles and fixtures shared by every crate in this workspace.
//!
//! * [`clock`] — a controllable fake clock implementing the domain's `Clock`
//!   port, so a five-minute idle timeout is tested in microseconds rather than
//!   slept through.
//! * [`fixtures`] — deterministic builders for hosts, policies, attempts, and
//!   queued jobs. Fixed ids and fixed timestamps, so a `g2` snapshot is
//!   reproducible.
//! * [`github`] — the fake GitHub gateway. Owned by group C.
//!
//! This crate is `publish = false` and is a dev-dependency everywhere.
//!
//! **One constraint to know before using it.** Because `testkit` depends on
//! `runner-manager-domain` while `runner-manager-domain` dev-depends on
//! `testkit`, a **unit** test inside `crates/domain/src/*.rs` cannot use these
//! helpers: Cargo compiles a second instance of the domain library for `testkit`
//! to link against, and the two instances' types do not unify. An **integration**
//! test under `crates/<crate>/tests/` is unaffected. The same applies to any
//! other crate that both this one depends on and that dev-depends on this one.

pub mod clock;
pub mod fixtures;
pub mod github;
