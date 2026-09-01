// owner: d1-platform-core
//
// d1 owns `os`, `paths`, `lock`, `process`, `logging` and this crate root;
// d2 owns `secrets`; d3 owns `service`.

//! Host primitives every other crate in `runner-manager` assumes exist.
//!
//! This crate is the whole of the surface where *"works on my machine"* becomes
//! *"works on Windows, macOS, and Linux"*. Everything above it — the domain, the
//! GitHub gateway, the agent, the CLI and the TUI — is written once and is
//! platform-blind; the three-way differences live here and nowhere else.
//!
//! | Module | Primitive | Whose Definition of Done depends on it |
//! |---|---|---|
//! | [`os`] | Host OS/architecture, and their standing in GitHub's documented support matrix | `f2` warns on ARM64 and reports the Linux-only container limitation |
//! | [`paths`] | The `config/`, `state/`, `runtime/`, `logs/` directories, in platform-standard locations | everything that touches disk |
//! | [`runner_root`] | Where runner workspaces go: the short `%SystemDrive%` default, and the local/writable/non-overlapping check every configured root passes | `b2`'s default-root ACL, `c1`'s ephemeral launch, `d1`'s mutations |
//! | [`lock`] | The single-instance lock and the runtime allocation lock | `e1`'s allocation, `e3`'s restart recovery |
//! | [`process`] | Spawn, observe, terminate; a process identity a recycled PID cannot forge; the restrictive JIT handoff | `e3` adopts a live process without starting a duplicate |
//! | [`logging`] | Structured allowlist logging with unconditional redaction | `07-security.md`'s secret-injection log scan |
//! | [`secrets`] | Machine-scoped secret store (`d2`) | |
//! | [`service`] | Service and daemon installers (`d3`) | |
//!
//! # Three properties worth knowing before reading any of it
//!
//! **A PID is not an identity.** [`process::ProcessIdentity`] pairs a PID with
//! a platform-defined start token, because the attempt journal outlives a
//! reboot and PIDs are reused. Adopting a stranger — or terminating one — is
//! the failure mode that primitive exists to prevent.
//!
//! **A lock is an operating-system file lock, not a PID file.** The requirement
//! is *"released on crash rather than leaking"*, and only the kernel can
//! deliver that for a process that was killed or whose machine lost power.
//!
//! **Redaction is allowlist-first and unconditional.** A field this crate has
//! not been told about is redacted, so a field added by a later task cannot
//! leak by default.
//!
//! # Platform coverage is a CI property, not a local one
//!
//! Each of these modules has a Windows path, a macOS path, and a Linux path,
//! and a developer's machine exercises exactly one of them. The contract tests
//! are written to run natively on all three legs of the CI matrix rather than
//! to be cross-compiled and assumed; where a test can only assert something on
//! one family — a Unix mode bit, a Windows DACL — it asserts the *property*
//! ("no other local user can read this") through a platform-specific check
//! behind one cross-platform name.

pub mod lock;
pub mod logging;
pub mod os;
pub mod paths;
pub mod process;
pub mod runner_root;
pub mod secrets;
pub mod service;
