//! `babbleon-daemon` — entry point.
//!
//! Phase-2 placeholder: parses the CLI, prints a clear "not yet
//! implemented" message for every subcommand.  The real loop lands
//! in a follow-up commit once the socket protocol and vault load
//! are designed (see `HANDOFF.md` "Phase-2 next steps").

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(clippy::pedantic)]

use clap::Parser;

use babbleon_daemon_v2::cli::{Args, Cmd};

fn main() -> std::process::ExitCode {
    let args = Args::parse();
    install_tracing(args.verbose);

    let result = match args.cmd {
        Cmd::Run => not_yet_implemented("run"),
        Cmd::EmitActivatedTable => not_yet_implemented("emit-activated-table"),
        Cmd::Status => not_yet_implemented("status"),
        Cmd::RotateMapping => not_yet_implemented("rotate-mapping"),
    };

    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("babbleon-daemon: {message}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn install_tracing(verbose: u8) {
    let default_level = match verbose {
        0 => "warn",
        1 => "info",
        _ => "debug",
    };
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default_level));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();
}

fn not_yet_implemented(command: &str) -> std::result::Result<(), String> {
    Err(format!(
        "`{command}` is not yet implemented; the daemon is a phase-2 \
         skeleton.  See HANDOFF.md for the remaining work.",
    ))
}
