mod advise;
mod analyze;
mod baseline;
mod cli;
mod collect;
mod compat;
mod demo;
mod ebpf;
mod error;
mod flame;
mod kallsyms;
mod model;
mod parse;
mod procs;
mod rate;
mod report;
mod session;
mod tui;

pub use error::{Error, Result};

pub fn cli_main() -> Result<()> {
    cli::run()
}
