// owner: a1-workspace-ci-foundation
//
// This file is the wiring seam between the CLI (group F) and the TUI (group G)
// and is deliberately final: neither group edits it, so neither group can
// conflict with the other here.
//
// The contract it fixes:
//
//   * `cli` owns the whole clap command tree, including the `tui` command
//     (`02-target-architecture.md` lists that surface exhaustively), and is the
//     composition root that wires domain, github, and platform together (`f1`).
//   * `cli::dispatch` is the single entry point and returns the process exit
//     code, so exit codes stay a CLI concern (`f3` requires distinct codes per
//     failure class).
//   * The `tui` command routes into `tui::run` (`g1`), which is the only door
//     into the terminal UI.

mod cli;
mod tui;

fn main() -> std::process::ExitCode {
    cli::dispatch()
}
