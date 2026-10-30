//! `omnisec` — universal binary analysis & exploit platform CLI.
//!
//! Phase 1 ships three subcommands:
//!
//! ```text
//! omnisec info <FILE>      Print loader summary (default).
//! omnisec disasm <FILE>    Linear-sweep disassembly of code sections.
//! omnisec version          Print version + build info.
//! ```
//!
//! The CLI is intentionally thin — every interesting bit of work lives in
//! the `omnisec-*` library crates, which are independently testable.

#![deny(missing_docs)]
#![forbid(unsafe_code)]

mod ansi;
mod app;
mod commands;
mod display;
mod error;
mod load;
mod logging;

use std::process::ExitCode;

use crate::ansi::Stylize;
use crate::app::Cli;

fn main() -> ExitCode {
    let cli = Cli::parse();
    crate::logging::init(cli.verbose);

    match cli.run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{}: {e:#}", "error".red());
            ExitCode::FAILURE
        }
    }
}
