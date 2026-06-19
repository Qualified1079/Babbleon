//! `babbleon-daemon` — entry point.
//!
//! Long-running mode and three operator one-shots.  Each one-shot
//! connects to the running daemon over its Unix socket and prints
//! the response to stdout; the long-running mode binds the socket
//! and serves until SIGTERM.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(clippy::pedantic)]

use std::process::ExitCode;

use clap::Parser;

use babbleon_daemon_v2::cli::{Args, Cmd, RunArgs};
use babbleon_daemon_v2::{
    apply_secret_hygiene, bind_socket, default_socket_path, round_trip,
    serve_blocking, DaemonState, ErrorKind, Request, Response,
};
use babbleon_core_v2::{PerHostSecret, Wordlist};

/// Development-only stub secret used in phase 2.  Replaced by vault
/// unlock in phase 3.  Sentinel value (0x42 repeating) makes it
/// obvious in a debugger / hexdump that this is not a real secret.
const INSECURE_STUB_SECRET: [u8; 32] = [0x42; 32];

fn main() -> ExitCode {
    let args = Args::parse();
    install_tracing(args.verbose);

    let socket_path = args
        .socket
        .clone()
        .unwrap_or_else(default_socket_path);

    let result = match args.cmd {
        Cmd::Run(run_args) => run_daemon(&socket_path, run_args),
        Cmd::Status => one_shot(&socket_path, &Request::Status),
        Cmd::EmitActivatedTable => {
            one_shot(&socket_path, &Request::EmitActivatedTable)
        }
        Cmd::RotateMapping => {
            one_shot(&socket_path, &Request::RotateMapping)
        }
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("babbleon-daemon: {message}");
            ExitCode::FAILURE
        }
    }
}

/// Long-running mode: bind the socket, build a `DaemonState`, serve.
fn run_daemon(
    socket_path: &std::path::Path,
    args: RunArgs,
) -> Result<(), String> {
    if !args.insecure_stub_secret {
        return Err(
            "phase 2 requires --insecure-stub-secret while real vault \
             unlock is pending.  Pass it explicitly to acknowledge that \
             this daemon will use a development-only hardcoded secret \
             (NOT for production)."
                .into(),
        );
    }

    // Security-baseline rule 8: harden BEFORE any secret enters
    // memory.  The next line builds a PerHostSecret; the hygiene
    // call has to come first.
    apply_secret_hygiene()
        .map_err(|e| format!("secret-hygiene startup: {e}"))?;

    let secret = PerHostSecret::from_bytes(&INSECURE_STUB_SECRET)
        .map_err(|e| format!("constructing stub secret: {e}"))?;
    let mut state = DaemonState::new(
        secret,
        Wordlist::english_baseline(),
        args.tracked_tools,
        args.wrapper_dir,
    )
    .map_err(|e| format!("constructing DaemonState: {e}"))?;

    let listener = bind_socket(socket_path)
        .map_err(|e| format!("bind {}: {e}", socket_path.display()))?;

    tracing::info!(
        socket = %socket_path.display(),
        "babbleon-daemon serving (phase 2 stub)",
    );

    serve_blocking(&mut state, &listener, |e| {
        tracing::warn!(error = %e, "per-connection error");
    })
    .map_err(|e| format!("serve loop: {e}"))?;
    Ok(())
}

/// One-shot: connect, send request, print response, exit.
fn one_shot(
    socket_path: &std::path::Path,
    request: &Request,
) -> Result<(), String> {
    let resp = round_trip(socket_path, request)
        .map_err(|e| format!("round-trip to daemon: {e}"))?;
    match resp {
        Response::Status {
            epoch,
            tracked_count,
            vault_locked,
            last_rotation_unix_secs,
        } => {
            println!(
                "epoch: {epoch}\ntracked_count: {tracked_count}\nvault_locked: {vault_locked}\nlast_rotation_unix_secs: {}",
                last_rotation_unix_secs
                    .map_or("null".to_string(), |s| s.to_string())
            );
        }
        Response::ActivatedTable { epoch: _, jsonl } => {
            // Write the JSONL verbatim so consumers can pipe it
            // directly into the launcher's `--activated-table-path`
            // input.
            use std::io::Write;
            std::io::stdout()
                .write_all(&jsonl)
                .map_err(|e| format!("write jsonl to stdout: {e}"))?;
        }
        Response::Rotated { new_epoch } => {
            println!("rotated to epoch: {new_epoch}");
        }
        Response::Error { kind, message } => {
            return Err(format!("daemon error ({kind:?}): {message}"));
        }
    }
    let _ = ErrorKind::Internal; // silence unused-import lint when no Error path is hit.
    Ok(())
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
