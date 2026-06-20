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

use babbleon_daemon_v2::cli::{Args, Cmd, ParsedTrackedTool, RunArgs};
use babbleon_daemon_v2::{
    apply_secret_hygiene, bind_socket, default_socket_path, round_trip,
    serve_blocking, DaemonState, ErrorKind, MaterializationConfig, Request,
    Response, TrackedTool,
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
    // Security-baseline rule 8: harden BEFORE any secret enters
    // memory.  Runs in both the Locked and Unlocked startup paths
    // because the Locked path will eventually receive a secret via
    // Request::Unlock.
    apply_secret_hygiene()
        .map_err(|e| format!("secret-hygiene startup: {e}"))?;

    let tracked = resolve_tracked_tools(args.tracked_tools)?;
    let materialization = MaterializationConfig {
        wrapper_dir: args.wrapper_dir,
        honey_list_path: None,
        stale_list_path: None,
        trusted_ns_inode: None,
    };
    // Default: start Locked and wait for the operator's `babbleon
    // unlock`.  Opt-in path: `--insecure-stub-secret` starts
    // Unlocked with the development-only sentinel secret (the
    // legacy phase-2 behaviour, retained for tests and for
    // operators who deliberately want a non-vault daemon).
    let mut state = if args.insecure_stub_secret {
        let secret = PerHostSecret::from_bytes(&INSECURE_STUB_SECRET)
            .map_err(|e| format!("constructing stub secret: {e}"))?;
        tracing::warn!(
            "babbleon-daemon: --insecure-stub-secret in use; \
             daemon starts in Unlocked with a development-only \
             hardcoded secret (NOT for production)",
        );
        DaemonState::new_unlocked(
            secret,
            Wordlist::english_baseline(),
            tracked,
            materialization,
        )
        .map_err(|e| format!("constructing DaemonState: {e}"))?
    } else {
        tracing::info!(
            "babbleon-daemon: starting Locked; awaiting `babbleon unlock` \
             from a peer (Request::Unlock over the socket)",
        );
        DaemonState::new_locked(
            Wordlist::english_baseline(),
            tracked,
            materialization,
        )
        .map_err(|e| format!("constructing DaemonState: {e}"))?
    };

    let listener = bind_socket(socket_path)
        .map_err(|e| format!("bind {}: {e}", socket_path.display()))?;

    // Surface the deprecated --enable-seccomp flag so a script
    // passing it learns to drop it before v2.1 retires it.
    if args.legacy_enable_seccomp {
        tracing::warn!(
            "babbleon-daemon: --enable-seccomp is deprecated and a no-op \
             (seccomp is on by default since the phase-2 close).  \
             Drop the flag; this warning will become a hard error in v2.1.",
        );
    }

    // Install seccomp BEFORE the serve loop — the filter excludes
    // socket/bind/listen (already done above) and prctl (already
    // done above), so the install order is mandatory.  See
    // docs/v2/daemon-seccomp-envelope.md.  Default is ON; --no-seccomp
    // is an opt-out for local development iteration.
    if args.disable_seccomp {
        tracing::warn!(
            "babbleon-daemon: seccomp NOT installed (--no-seccomp passed).  \
             NOT recommended for production; envelope in \
             docs/v2/daemon-seccomp-envelope.md.",
        );
    } else {
        #[cfg(target_os = "linux")]
        babbleon_daemon_v2::seccomp_profile::apply().map_err(|e| {
            format!("seccomp profile install: {e}")
        })?;
        tracing::info!(
            "babbleon-daemon: seccomp allowlist installed (36 syscalls; \
             envelope in docs/v2/daemon-seccomp-envelope.md)",
        );
    }

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
        Response::Unlocked { epoch } => {
            // Operator-side daemon-binary one-shots never send Unlock
            // (that's the user-CLI's responsibility).  An Unlocked
            // reply here means we asked Status and the daemon mis-
            // dispatched, or a future verb returns Unlocked too — so
            // we print it rather than panic.
            println!("unlocked at epoch: {epoch}");
        }
        Response::Error { kind, message } => {
            return Err(format!("daemon error ({kind:?}): {message}"));
        }
    }
    let _ = ErrorKind::Internal; // silence unused-import lint when no Error path is hit.
    Ok(())
}

/// Resolve every parsed `--tracked-tool` to an absolute real-binary
/// path.  Explicit `NAME=PATH` entries are accepted as-is; bare
/// `NAME` entries are searched for in `$PATH` via [`which_in_path`].
/// An unresolved name is a fatal startup error (the operator
/// intended to track a binary that does not exist on this host).
fn resolve_tracked_tools(
    parsed: Vec<ParsedTrackedTool>,
) -> Result<Vec<TrackedTool>, String> {
    let path_env = std::env::var_os("PATH").unwrap_or_default();
    let mut out = Vec::with_capacity(parsed.len());
    for p in parsed {
        let real_path = match p.real_path {
            Some(explicit) => explicit,
            None => which_in_path(&p.name, &path_env).ok_or_else(|| {
                format!(
                    "tracked tool {:?} not found in $PATH; pass --tracked-tool {0}=/abs/path \
                     to override",
                    p.name,
                )
            })?,
        };
        out.push(TrackedTool {
            name: p.name,
            real_path,
        });
    }
    Ok(out)
}

/// Return the first absolute path in `$PATH` that names an executable
/// file called `name`.  We deliberately do NOT use the `which` crate
/// — adding a dependency for a 12-line PATH walk is not worth the
/// audit surface.
fn which_in_path(
    name: &str,
    path_env: &std::ffi::OsStr,
) -> Option<std::path::PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    for dir in std::env::split_paths(path_env) {
        let candidate = dir.join(name);
        let Ok(meta) = std::fs::metadata(&candidate) else { continue };
        if !meta.is_file() {
            continue;
        }
        if meta.permissions().mode() & 0o111 == 0 {
            continue;
        }
        if candidate.is_absolute() {
            return Some(candidate);
        }
    }
    None
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
