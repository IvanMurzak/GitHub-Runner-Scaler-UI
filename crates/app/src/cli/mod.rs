// owner: f1-cli-auth-host-status
//
// f1 owns this module list and `dispatch`, plus `auth`, `host` and `status`;
// f2 owns `policy`; f3 owns `daemon` and `service`.

pub mod auth;
pub mod daemon;
pub mod host;
pub mod policy;
pub mod service;
pub mod status;

use std::process::ExitCode;

/// The single entry point `main` calls.
///
/// `f1` replaces this body with the clap command tree from
/// `02-target-architecture.md`. Two properties of the skeleton must survive
/// that replacement:
///
/// * it returns a [`ExitCode`], because `f3` needs distinct exit codes per
///   failure class;
/// * the `tui` command calls [`crate::tui::run`] and nothing else reaches the
///   terminal UI, which is what keeps `main.rs` — a file neither group F nor
///   group G owns — from ever needing an edit.
pub fn dispatch() -> ExitCode {
    if std::env::args_os().nth(1).is_some_and(|arg| arg == "tui") {
        return crate::tui::run();
    }

    eprintln!("runner-manager: the command surface is not implemented yet (task f1).");
    ExitCode::FAILURE
}
