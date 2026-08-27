// owner: g1-tui-shell-input
//
// g1 owns this module list, `run`, and `shell`; g2 owns `screens` and the
// `table` grid it draws with; g3 owns `settings`.

pub mod screens;
pub mod settings;
pub mod shell;
pub mod table;

use std::process::ExitCode;
use std::sync::Arc;

/// The only door into the terminal UI; `cli::dispatch` routes `tui` here.
pub fn run(data_dir: Option<&std::path::Path>) -> ExitCode {
    let mut err = std::io::stderr();
    let context = match crate::cli::Context::resolve(data_dir, &mut err) {
        Ok(context) => Arc::new(context),
        Err(error) => {
            let _ = error.render(&mut err);
            return ExitCode::from(error.class().code());
        }
    };
    match shell::run_terminal(context) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("runner-manager: terminal UI failed: {error}");
            ExitCode::FAILURE
        }
    }
}
