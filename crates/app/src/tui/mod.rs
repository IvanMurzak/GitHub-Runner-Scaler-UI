// owner: g1-tui-shell-input
//
// g1 owns this module list, `run`, and `shell`; g2 owns `screens`; g3 owns
// `settings`.

pub mod screens;
pub mod settings;
pub mod shell;

use std::process::ExitCode;

/// The only door into the terminal UI; `cli::dispatch` routes `tui` here.
pub fn run() -> ExitCode {
    match shell::run_terminal() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("runner-manager: terminal UI failed: {error}");
            ExitCode::FAILURE
        }
    }
}
