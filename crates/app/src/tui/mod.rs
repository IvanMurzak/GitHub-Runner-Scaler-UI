// owner: g1-tui-shell-input
//
// g1 owns this module list, `run`, and `shell`; g2 owns `screens`; g3 owns
// `settings`.

pub mod screens;
pub mod settings;
pub mod shell;

use std::process::ExitCode;

/// The only door into the terminal UI; `cli::dispatch` routes the `tui`
/// command here.
///
/// `g1` replaces this body with the terminal setup from `03-control-flows.md`
/// flow 6.1 — raw mode, the alternate screen, and `EnableMouseCapture`, which
/// `ratatui::init()` does not enable on its own — and with the merged event
/// stream that feeds the reducer.
pub fn run() -> ExitCode {
    eprintln!("runner-manager: the terminal UI is not implemented yet (task g1).");
    ExitCode::FAILURE
}
