//! `babbleon-python` — entry point.
//!
//! See `lib.rs` for the threat model and pipeline overview.
//!
//! # Argv contract
//!
//! ```text
//! babbleon-python [SHIM-FLAGS] SCRIPT.py [PYTHON-ARGS...]
//! ```
//!
//! Shim flags (all `--double-dash` to avoid collision with python's
//! single-dash short options):
//!
//! - `--socket PATH` — override daemon socket path.
//! - `--python PATH` — interpreter binary path (default
//!   `/usr/bin/python3`).
//! - `-v` / `--verbose` — bump logging.
//!
//! Every argv beyond `SCRIPT.py` is forwarded to python verbatim.
//! Operator usage: `babbleon-python encrypted.py --my-arg` reaches
//! python as `python3 - --my-arg` with the unscrambled source piped
//! to stdin.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(clippy::pedantic)]

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::Parser;

use babbleon_daemon_protocol_v2::default_socket_path;
use babbleon_python_shim_v2::pipeline::unscramble_full;
use babbleon_python_shim_v2::{exec_python, process_hardening};

/// Babbleon v2 — layer-3 Python shim.
#[derive(Parser)]
#[command(
    name = "babbleon-python",
    bin_name = "babbleon-python",
    version,
    about = "Run a layer-3 scrambled Python source via python3 + pipe(2)",
)]
struct Cli {
    /// Verbosity.  `-v` enables INFO; `-vv` enables DEBUG.
    #[arg(short = 'v', long = "verbose", action = clap::ArgAction::Count)]
    verbose: u8,

    /// Override the daemon Unix-socket path.  Defaults to the
    /// production location (`/run/babbleon/daemon.sock`).
    #[arg(long = "socket", value_name = "PATH")]
    socket: Option<PathBuf>,

    /// Override the python interpreter.  Defaults to
    /// `/usr/bin/python3`.
    #[arg(long = "python", value_name = "PATH")]
    python: Option<PathBuf>,

    /// Scrambled Python source file to run.
    script: PathBuf,

    /// Trailing arguments forwarded to the python interpreter.
    /// Visible inside the script as `sys.argv[1:]`.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    python_args: Vec<String>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    install_tracing(cli.verbose);

    let socket = cli.socket.unwrap_or_else(default_socket_path);
    let python = cli.python.unwrap_or_else(default_python_path);

    let result: Result<i32> = run_shim(&socket, &python, &cli.script, &cli.python_args);

    match result {
        Ok(code) => {
            // Propagate the child's exit code.  `i32` -> `ExitCode`
            // narrows to `u8` per the documented contract; we mask
            // to avoid negative or oversize codes.
            #[allow(clippy::cast_sign_loss)]
            let masked = (code & 0xff) as u8;
            ExitCode::from(masked)
        }
        Err(e) => {
            eprintln!("babbleon-python: {e}");
            let mut source = e.source();
            while let Some(s) = source {
                eprintln!("  caused by: {s}");
                source = s.source();
            }
            ExitCode::FAILURE
        }
    }
}

/// Run the shim pipeline; return the child's exit code (or 128 +
/// signal if killed by a signal).
fn run_shim(
    socket: &std::path::Path,
    python: &std::path::Path,
    script: &std::path::Path,
    forward_args: &[String],
) -> Result<i32> {
    // (1) Process hygiene before any I/O or secret-adjacent bytes
    //     reach memory.
    process_hardening::apply().context("apply process hardening")?;

    // (2) Read scrambled source.  No daemon traffic yet — fail
    //     here if the file does not exist without bothering the
    //     daemon.
    let scrambled = std::fs::read_to_string(script)
        .with_context(|| format!("read scrambled script {}", script.display()))?;

    // (3) Drive the full unscramble pipeline.  Internally:
    //     - parse the scrambled-file header (version, epoch, sorted
    //       tokens, L3 body),
    //     - fetch whitespace compounds (`GetWhitespaceCompounds`),
    //     - fetch identifier mapping (`GetTokenMapping`) pinned to the
    //       header's epoch,
    //     - apply L12⁻¹ → L6⁻¹ → L3⁻¹ → L2⁻¹ → L5⁻¹ → L4⁻¹ →
    //       tokens_to_source.
    //     The same composition the user CLI and the corpus CLI use;
    //     all three call sites consume
    //     `babbleon_preprocessor_v2::pipeline`.
    let source = unscramble_full(socket, &scrambled)?;

    // (4-6) Spawn python3 -, feed source, wait.
    let status = exec_python::run(python, forward_args, &source)?;

    // ExitStatus -> i32.  On Unix, `.code()` returns None for
    // signal-killed children; we map that to 128 + signal per the
    // shell convention.
    let code = status.code().unwrap_or_else(|| {
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            128 + status.signal().unwrap_or(0)
        }
        #[cfg(not(unix))]
        {
            1
        }
    });
    Ok(code)
}

/// Default python interpreter path.
///
/// Hardcoded `/usr/bin/python3` matches the operator-confirmed
/// install layout from `docs/v2/least-privilege.md`.  Override
/// via `--python` for non-default installs.
fn default_python_path() -> PathBuf {
    PathBuf::from("/usr/bin/python3")
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

#[cfg(test)]
mod tests {
    use super::Cli;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn script_path_required() {
        let r = Cli::command().try_get_matches_from(["babbleon-python"]);
        assert!(r.is_err(), "script path must be required");
    }

    #[test]
    fn script_path_alone_parses() {
        let r = Cli::command()
            .try_get_matches_from(["babbleon-python", "foo.py"]);
        assert!(r.is_ok());
    }

    #[test]
    fn forwards_trailing_args() {
        let r = Cli::command().try_get_matches_from([
            "babbleon-python",
            "foo.py",
            "--my-arg",
            "value",
        ]);
        assert!(r.is_ok());
    }

    #[test]
    fn socket_override_parses() {
        let r = Cli::command().try_get_matches_from([
            "babbleon-python",
            "--socket",
            "/tmp/babbleon.sock",
            "foo.py",
        ]);
        assert!(r.is_ok());
    }

    #[test]
    fn python_override_parses() {
        let r = Cli::command().try_get_matches_from([
            "babbleon-python",
            "--python",
            "/opt/python/3.11/bin/python3",
            "foo.py",
        ]);
        assert!(r.is_ok());
    }

    #[test]
    fn default_python_path_is_usr_bin() {
        assert_eq!(
            super::default_python_path(),
            std::path::PathBuf::from("/usr/bin/python3"),
        );
    }
}
