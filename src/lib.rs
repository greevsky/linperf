mod advise;
mod analyze;
mod baseline;
mod bench;
mod board;
mod cli;
mod collect;
mod compat;
mod containers;
mod demo;
mod ebpf;
mod error;
mod flame;
mod identity;
mod kallsyms;
mod model;
mod parse;
mod procs;
mod rate;
mod report;
mod session;
mod sniff;
mod syslog;
mod tui;

pub use error::{Error, Result};
pub use identity::COMMAND;

pub fn cli_main() -> Result<()> {
    cli::run()
}
