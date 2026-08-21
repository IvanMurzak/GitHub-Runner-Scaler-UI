// owner: b1-domain-core
//
// The module list is created by a1 so that neither b1 nor b2 has to edit it.
// `store` belongs to b2; every other module belongs to b1.

//! The deterministic core every other crate is measured against.
//!
//! Everything here is decidable without a network, a filesystem, or a clock.
//! That is not an aesthetic preference — it is the property that makes the rest
//! of the product testable, and each module states how it keeps it:
//!
//! * [`model`] — value types, and the [`model::Clock`] port that is the only
//!   source of "now" in the crate.
//! * [`policy`] — routing-label derivation and `runs-on` matching (D4), the
//!   monitor-only/autoscale split (D19), and the policy lifecycle.
//! * [`attempt`] — the runner-attempt lifecycle, its outcome, ownership, and
//!   restart-recovery decisions.
//! * [`capacity`] — the two-level ceiling (D7, D9), as an allocator over all
//!   policies rather than a check a caller may forget.
//! * [`store`] — SQLite persistence. Owned by `b2`, and the only module here
//!   that touches I/O.
//!
//! **There is no job reservation anywhere in this crate, and none may be added.**
//! `AcquireJobs` has no REST equivalent, so demand is advisory and a second host
//! may take a job this one has already started a runner for
//! (`01-current-architecture.md`, edge case 6). The surplus runner that results
//! is an accepted, bounded cost, not a defect to engineer around: the bounding
//! controls are the host-scoped routing label
//! ([`policy::RoutingLabels::derive`]) and the two capacity ceilings
//! ([`capacity::HostAllocator`]). A lease, claim, or local reservation table
//! added here would not remove the surplus case — it would only hide it from the
//! tests that measure it.

pub mod attempt;
pub mod capacity;
pub mod model;
pub mod policy;
pub mod store;
