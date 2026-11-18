//! `kw` — command-line client for Keyward. (`keyward` offers the same
//! commands and opens the TUI when run without one.)
#![forbid(unsafe_code)]

use std::process::ExitCode;

use clap::Parser;
use keyward_cli::cli::Cli;

fn main() -> ExitCode {
    match keyward_cli::run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}
