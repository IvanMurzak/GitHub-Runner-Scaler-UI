// owner: g1-tui-shell-input
//
// g1 owns this module list, `run`, and `shell`; g2 owns `screens` and the
// `table` grid it draws with; g3 owns `settings`. `e1-workspace-tui` adds
// `path_field`, the editable path control both settings screens use.

pub mod path_field;
pub mod screens;
pub mod settings;
pub mod shell;
pub mod table;

use std::process::ExitCode;
use std::sync::Arc;

/// One rendered frame as the terminal would show it. `TestBackend`'s own
/// `Display` quotes every row and appends multi-width notes, which the tests
/// index into by column, so they read the cells directly instead.
#[cfg(test)]
pub fn buffer_text(buffer: &ratatui::buffer::Buffer) -> String {
    let area = buffer.area();
    (0..area.height)
        .map(|y| {
            (0..area.width)
                .map(|x| buffer[(x, y)].symbol())
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join(
            "
",
        )
}

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
