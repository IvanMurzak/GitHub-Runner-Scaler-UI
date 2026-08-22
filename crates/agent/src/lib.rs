// owner: e1-reconciliation-capacity
//
// e1 owns `reconcile` and this crate root, e2 owns `package`, e3 owns
// `lifecycle`. The module list is `a1`'s, so neither of the other two has to
// edit this file.

//! The host agent: demand reconciliation, the runner package cache, and the
//! just-in-time runner lifecycle.
//!
//! * [`reconcile`] — the loop that turns GitHub demand into a decision to start
//!   runners, and the two ceilings that bound it. It owns no I/O of its own:
//!   every effect it has reaches the world through a port, which is what makes
//!   the whole decision path testable with no process, no filesystem and no
//!   network.
//! * [`package`] — the cached, checksum-verified GitHub runner package. `e2`
//!   owns it, and it is an ownership stub today.
//! * [`lifecycle`] — the JIT registration, the child process, and restart
//!   recovery. `e3` owns it and **will** implement
//!   [`reconcile::RunnerLauncher`]; it is an ownership stub today, so the port
//!   has no production implementation yet. Written in the future tense on
//!   purpose: a crate root that describes a stub as if it were finished is how
//!   a reader concludes the wiring exists and goes looking for the bug
//!   somewhere else.
//!
//! # Every ceiling in this product is enforced in this crate
//!
//! `max_capacity` beats reported demand and `Host.host_capacity` beats
//! `max_capacity`, across **all** policies on the machine (D7, D9). The
//! arithmetic belongs to
//! [`runner_manager_domain::capacity::HostAllocator`]; what this crate adds is
//! the two things the arithmetic cannot supply for itself — the attempt set the
//! host actually holds, and the host-wide allocation lock that makes reading it
//! and acting on it one indivisible step.
//!
//! **There is no job reservation anywhere in this crate, and none may be
//! added.** `AcquireJobs` has no REST equivalent, so demand is advisory and a
//! second host may take a job this one has already started a runner for. The
//! surplus runner that results exits on its idle timeout and is cleaned like any
//! other attempt; it is an accepted, bounded cost rather than a defect to
//! engineer around. [`reconcile`] states the full reasoning and carries a
//! tripwire against the shape being reintroduced.

pub mod lifecycle;
pub mod package;
pub mod reconcile;
