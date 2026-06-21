//! `babbleon-login-shell` — entry point.
//!
//! Resolves environment overrides, builds the launcher argv, and
//! `exec`s the launcher.  On exec failure prints to stderr and
//! exits non-zero so login fails loudly (per the F1 design — a
//! silent failure here would defeat the wrap).

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(clippy::pedantic)]

use std::ffi::OsString;
use std::os::unix::process::CommandExt;
use std::process::ExitCode;

use babbleon_login_shell_v2::{build_argv, resolve};

fn main() -> ExitCode {
    // Tracing is OPT-IN via `RUST_LOG`.  Default behaviour for a
    // login shell is silence; operators chasing a regression set
    // `RUST_LOG=info` and reproduce.
    if std::env::var_os("RUST_LOG").is_some() {
        let filter = tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(std::io::stderr)
            .init();
    }

    let argv: Vec<OsString> = std::env::args_os().collect();
    let inv = resolve(&argv);
    let launcher_argv = build_argv(&inv);

    tracing::info!(
        launcher = %inv.launcher_path.display(),
        socket = %inv.daemon_socket_path.display(),
        shell = %inv.real_shell.display(),
        forwarded = inv.forwarded_args.len(),
        "babbleon-login-shell exec",
    );

    let program = &launcher_argv[0];
    let mut cmd = std::process::Command::new(program);
    cmd.args(&launcher_argv[1..]);
    let err = cmd.exec();
    // exec(2) only returns on failure; surface what went wrong so
    // a sysadmin reading auth.log can attribute the failure.
    eprintln!(
        "babbleon-login-shell: exec {}: {err}",
        inv.launcher_path.display(),
    );
    ExitCode::FAILURE
}
