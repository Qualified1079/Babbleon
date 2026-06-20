//! Babbleon v2 — user-facing CLI.
//!
//! # What this defeats
//!
//! Operators need a stable, scriptable interface for vault lifecycle
//! and tier inspection.  v1's CLI accreted commands ad-hoc; v2 ships
//! a fixed five-verb surface from day one (`init`, `unlock`,
//! `rotate-mapping`, `status`, `mount-scrambled-view`) plus acronym
//! aliases per `docs/v2/naming-conventions.md`.  Every action that
//! changes policy authenticates the operator; every read-only action
//! is documented as not requiring authentication so scripts can
//! depend on it.
//!
//! # Compartmentalization
//!
//! This binary does NOT hold the host secret or the epoch key in its
//! own address space for any longer than one `unlock` call needs.
//! The seal / unseal happens in [`vault_lifecycle`] inside the
//! one-shot stack frame; the unwrapped 32 bytes are immediately
//! handed to the daemon over the socket and dropped (Zeroizing wipes).
//! Privileged operations (mounting, sealing the vault) are dispatched
//! to the daemon over a local Unix socket; this process is a thin
//! client.
//!
//! Phase 3 wires `init` and `unlock` end-to-end.
//! `mount-scrambled-view` remains stubbed; it lands with the
//! launcher integration in a later phase.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(clippy::pedantic)]

mod corpus_lifecycle;
mod passphrase;
mod scramble_lifecycle;
mod vault_lifecycle;

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use babbleon_daemon_protocol_v2::{
    default_socket_path, round_trip, Request, Response,
};

use corpus_lifecycle::{
    run_scramble_dir, run_unscramble_dir, CorpusOptions, CorpusReport,
};
use scramble_lifecycle::{
    run_scramble, run_unscramble, InputSource, OutputSink, ScrambleOptions,
};
use vault_lifecycle::{
    run_init, run_unlock, InitOptions, PassphraseSource, UnlockOptions,
};

/// Top-level CLI.  The bare `babbleon` invocation prints help.
#[derive(Parser)]
#[command(
    name = "babbleon",
    bin_name = "babbleon",
    version,
    about = "Per-host randomized namespace obfuscation (v2)",
    long_about = "Babbleon v2 control surface.  See docs/v2/ for design.",
)]
struct Cli {
    /// Verbosity.  `-v` enables INFO; `-vv` enables DEBUG.  No flag =
    /// WARN and above (errors only on success paths).
    #[arg(short = 'v', long = "verbose", action = clap::ArgAction::Count, global = true)]
    verbose: u8,

    /// Override the daemon's Unix-socket path.  Defaults to the
    /// production location (`/run/babbleon/daemon.sock`); override
    /// for tests or non-default installs.
    #[arg(long = "socket", value_name = "PATH", global = true)]
    socket: Option<PathBuf>,

    /// Override the vault file path.  Defaults to
    /// `babbleon_vault_v2::default_vault_path()` —
    /// `$XDG_CONFIG_HOME/babbleon/vault.age` for per-user installs
    /// or `/etc/babbleon/vault.age` for system installs.  Only the
    /// `init` and `unlock` subcommands honour this flag.
    #[arg(long = "vault-path", value_name = "PATH", global = true)]
    vault_path: Option<PathBuf>,

    /// Read the passphrase from the first line of stdin instead of
    /// prompting via the controlling TTY.  Use this for CI scripts
    /// and integration tests; do NOT use it interactively (the
    /// passphrase would echo).
    #[arg(long = "passphrase-stdin", global = true)]
    passphrase_stdin: bool,

    #[command(subcommand)]
    cmd: Cmd,
}

/// Subcommands.
///
/// Naming follows `docs/v2/naming-conventions.md`: plain-English
/// verb-first names are the primary form.  Acronym aliases are
/// declared via `alias = "..."` on each variant.
#[derive(Subcommand)]
enum Cmd {
    /// Create a new vault on this host.  Generates the per-host
    /// secret, seals it under the configured credential backend,
    /// and writes the vault file.  Run once per host.  Refuses to
    /// overwrite an existing vault unless `--force` is supplied.
    Init {
        /// Acknowledge that re-init destroys the existing per-host
        /// mapping (all previously-issued wrappers, all audit
        /// records keyed off the old secret).  Required when the
        /// vault file already exists at `--vault-path`.
        #[arg(long = "force")]
        force: bool,
    },

    /// Unlock the vault for the current session.  Prompts for the
    /// passphrase (or reads stdin under `--passphrase-stdin`),
    /// decrypts the on-disk vault locally, then ships the 32-byte
    /// per-host secret to the daemon via the `Unlock` request.  The
    /// daemon then holds the secret in `mlock`'d memory until
    /// session end.
    Unlock,

    /// Bump the epoch and reseal the vault with a fresh permutation.
    /// Previous scrambled names enter the stale window and start
    /// firing tripwires; new wrappers see new compounds on next
    /// exec.
    #[command(name = "rotate-mapping", alias = "rm")]
    RotateMapping,

    /// Print vault state (epoch, tool count, last rotation) without
    /// unsealing the vault.  Read-only; safe to run from cron.
    Status,

    /// Apply the scrambled view to the current mount namespace.
    /// Requires the launcher's file capabilities; rejects if run
    /// from inside an already-scrambled namespace.
    #[command(name = "mount-scrambled-view", alias = "msv")]
    MountScrambledView,

    /// Scramble a Python source file via the per-epoch whitespace
    /// mapping the daemon is currently serving.  Reads the source
    /// from `--input` (or stdin if absent / `-`), writes scrambled
    /// bytes to `--output` (or stdout).  Requires the daemon to be
    /// running and unlocked.
    ///
    /// Trust-tier only: the daemon's socket permissions gate which
    /// peers can request the whitespace compounds.  This subcommand
    /// does NOT hold the per-host secret in the CLI process's
    /// memory at any point — see `scramble_lifecycle`'s module doc
    /// for the compartmentalisation argument.
    Scramble {
        /// Source file to scramble.  Use `-` or omit for stdin.
        #[arg(short = 'i', long = "input", value_name = "PATH")]
        input: Option<PathBuf>,
        /// Output path for scrambled bytes.  Use `-` or omit for
        /// stdout.
        #[arg(short = 'o', long = "output", value_name = "PATH")]
        output: Option<PathBuf>,
    },

    /// Inverse of `scramble`: read scrambled bytes, decode against
    /// the daemon's current whitespace mapping, write reconstructed
    /// Python source.  Same input / output flags and trust-tier
    /// constraints as `scramble`.
    Unscramble {
        /// Scrambled file to unscramble.  Use `-` or omit for
        /// stdin.
        #[arg(short = 'i', long = "input", value_name = "PATH")]
        input: Option<PathBuf>,
        /// Output path for the reconstructed source.  Use `-` or
        /// omit for stdout.
        #[arg(short = 'o', long = "output", value_name = "PATH")]
        output: Option<PathBuf>,
    },

    /// Recursively scramble every `.py` file under `--input-dir`
    /// to the same relative path under `--output-dir`.  Fetches
    /// per-epoch compounds from the daemon ONCE up-front; no
    /// per-file round-trip.  Operator typically runs this at
    /// install time over a vendored Python tree.
    #[command(name = "scramble-dir")]
    ScrambleDir {
        /// Source tree to read.
        #[arg(long = "input-dir", value_name = "PATH")]
        input_dir: PathBuf,
        /// Destination tree to write.  Must not exist (or be
        /// empty) unless `--force` is supplied.
        #[arg(long = "output-dir", value_name = "PATH")]
        output_dir: PathBuf,
        /// Permit writing into a non-empty output directory.
        #[arg(long = "force")]
        force: bool,
    },

    /// Inverse of `scramble-dir`: walk a tree of scrambled `.py`
    /// files and write reconstructed sources to the same relative
    /// paths under `--output-dir`.  Same flags as `scramble-dir`.
    #[command(name = "unscramble-dir")]
    UnscrambleDir {
        /// Source tree to read.
        #[arg(long = "input-dir", value_name = "PATH")]
        input_dir: PathBuf,
        /// Destination tree to write.
        #[arg(long = "output-dir", value_name = "PATH")]
        output_dir: PathBuf,
        /// Permit writing into a non-empty output directory.
        #[arg(long = "force")]
        force: bool,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    install_tracing(cli.verbose);

    let socket_path = cli.socket.clone().unwrap_or_else(default_socket_path);
    let passphrase_source = if cli.passphrase_stdin {
        PassphraseSource::Stdin
    } else {
        PassphraseSource::Interactive
    };

    let result: Result<()> = match cli.cmd {
        Cmd::Init { force } => run_init(InitOptions {
            vault_path: cli.vault_path.clone(),
            passphrase_source,
            allow_overwrite: force,
        }),
        Cmd::Unlock => run_unlock(UnlockOptions {
            vault_path: cli.vault_path.clone(),
            passphrase_source,
            socket_path: socket_path.clone(),
        }),
        Cmd::RotateMapping => run_rotate_mapping(&socket_path),
        Cmd::Status => run_status(&socket_path),
        // Phase 3+: needs the launcher binary on PATH and the PAM
        // module wired.
        Cmd::MountScrambledView => not_yet_implemented("mount-scrambled-view"),
        Cmd::Scramble { input, output } => run_scramble(ScrambleOptions {
            input: input_source_from(input),
            output: output_sink_from(output),
            socket_path: socket_path.clone(),
        }),
        Cmd::Unscramble { input, output } => run_unscramble(ScrambleOptions {
            input: input_source_from(input),
            output: output_sink_from(output),
            socket_path: socket_path.clone(),
        }),
        Cmd::ScrambleDir {
            input_dir,
            output_dir,
            force,
        } => run_scramble_dir(CorpusOptions {
            input_dir,
            output_dir,
            allow_overwrite: force,
            socket_path: socket_path.clone(),
        })
        .map(print_corpus_report),
        Cmd::UnscrambleDir {
            input_dir,
            output_dir,
            force,
        } => run_unscramble_dir(CorpusOptions {
            input_dir,
            output_dir,
            allow_overwrite: force,
            socket_path: socket_path.clone(),
        })
        .map(print_corpus_report),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            // Print the error chain with no backtrace noise.  anyhow's
            // default Debug-format for main()'s Result includes a
            // backtrace; we want a one-line operator-readable message
            // followed by the cause chain.
            eprintln!("babbleon: {e}");
            let mut source = e.source();
            while let Some(s) = source {
                eprintln!("  caused by: {s}");
                source = s.source();
            }
            ExitCode::FAILURE
        }
    }
}

/// Read-only status: connects to the daemon, prints the current
/// epoch, the tracked-tool count, the vault-locked state, and the
/// last-rotation timestamp (or `null` if the clock is pre-UNIX).
fn run_status(socket_path: &std::path::Path) -> Result<()> {
    let resp = round_trip(socket_path, &Request::Status)
        .with_context(|| format!("daemon round-trip via {}", socket_path.display()))?;
    match resp {
        Response::Status {
            epoch,
            tracked_count,
            vault_locked,
            last_rotation_unix_secs,
        } => {
            println!("epoch: {epoch}");
            println!("tracked_count: {tracked_count}");
            println!("vault_locked: {vault_locked}");
            println!(
                "last_rotation_unix_secs: {}",
                last_rotation_unix_secs
                    .map_or("null".to_string(), |s| s.to_string()),
            );
            Ok(())
        }
        Response::Error { kind, message } => {
            anyhow::bail!("daemon error ({kind:?}): {message}")
        }
        other => anyhow::bail!("expected Status response, got {other:?}"),
    }
}

/// Mutator: bump the epoch and rebuild.  Prints the new epoch on
/// success.
fn run_rotate_mapping(socket_path: &std::path::Path) -> Result<()> {
    let resp = round_trip(socket_path, &Request::RotateMapping)
        .with_context(|| format!("daemon round-trip via {}", socket_path.display()))?;
    match resp {
        Response::Rotated { new_epoch } => {
            println!("rotated to epoch: {new_epoch}");
            Ok(())
        }
        Response::Error { kind, message } => {
            anyhow::bail!("daemon error ({kind:?}): {message}")
        }
        other => anyhow::bail!("expected Rotated response, got {other:?}"),
    }
}

/// Set up structured logging.  Verbosity is additive over the
/// `RUST_LOG` environment override so operators can drop into
/// `tracing-subscriber`'s full filter syntax when needed.
fn install_tracing(verbose: u8) {
    let default_level = match verbose {
        0 => "warn",
        1 => "info",
        _ => "debug",
    };
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default_level));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

/// Placeholder.  Returns Err so scripts surface the gap loudly
/// instead of silently succeeding.
fn not_yet_implemented(command: &str) -> Result<()> {
    anyhow::bail!(
        "`{command}` is not yet implemented; \
         see V2_PLAN.md for the phase roadmap",
    )
}

/// Map `clap`'s `Option<PathBuf>` (with `-` sentinel for stdin) onto
/// the `InputSource` enum the scramble-lifecycle pipeline consumes.
fn input_source_from(path: Option<PathBuf>) -> InputSource {
    match path {
        None => InputSource::Stdin,
        Some(p) if p.as_os_str() == "-" => InputSource::Stdin,
        Some(p) => InputSource::File(p),
    }
}

/// Map `clap`'s `Option<PathBuf>` (with `-` sentinel for stdout)
/// onto the `OutputSink` enum.
fn output_sink_from(path: Option<PathBuf>) -> OutputSink {
    match path {
        None => OutputSink::Stdout,
        Some(p) if p.as_os_str() == "-" => OutputSink::Stdout,
        Some(p) => OutputSink::File(p),
    }
}

/// Pretty-print a [`CorpusReport`] to stdout after a successful
/// `scramble-dir` / `unscramble-dir` run.
fn print_corpus_report(report: CorpusReport) {
    let CorpusReport {
        files_transformed,
        bytes_in,
        bytes_out,
        elapsed_ms,
    } = report;
    println!("files_transformed: {files_transformed}");
    println!("bytes_in: {bytes_in}");
    println!("bytes_out: {bytes_out}");
    println!("elapsed_ms: {elapsed_ms}");
}

#[cfg(test)]
mod tests {
    use super::Cli;
    use super::{InputSource, OutputSink};
    use clap::CommandFactory;
    use std::path::PathBuf;

    #[test]
    fn clap_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn acronym_alias_rm_routes_to_rotate_mapping() {
        // Use `try_get_matches_from` rather than `parse_from` so a
        // routing failure becomes a test failure rather than a panic.
        let m = Cli::command().try_get_matches_from(["babbleon", "rm"]);
        assert!(m.is_ok(), "alias `rm` must route to a subcommand");
    }

    #[test]
    fn acronym_alias_msv_routes_to_mount_scrambled_view() {
        let m = Cli::command().try_get_matches_from(["babbleon", "msv"]);
        assert!(m.is_ok(), "alias `msv` must route to a subcommand");
    }

    #[test]
    fn vault_path_global_flag_parses() {
        let m = Cli::command().try_get_matches_from([
            "babbleon",
            "--vault-path",
            "/tmp/vault.age",
            "status",
        ]);
        assert!(m.is_ok(), "--vault-path must be a global flag");
    }

    #[test]
    fn passphrase_stdin_global_flag_parses() {
        let m = Cli::command().try_get_matches_from([
            "babbleon",
            "--passphrase-stdin",
            "unlock",
        ]);
        assert!(m.is_ok(), "--passphrase-stdin must be a global flag");
    }

    #[test]
    fn init_accepts_force_flag() {
        let m = Cli::command().try_get_matches_from([
            "babbleon", "init", "--force",
        ]);
        assert!(m.is_ok());
    }

    #[test]
    fn scramble_with_no_flags_parses() {
        let m = Cli::command().try_get_matches_from(["babbleon", "scramble"]);
        assert!(m.is_ok(), "`scramble` with no args must parse");
    }

    #[test]
    fn scramble_with_input_and_output_paths_parses() {
        let m = Cli::command().try_get_matches_from([
            "babbleon",
            "scramble",
            "--input",
            "in.py",
            "--output",
            "out.scr",
        ]);
        assert!(m.is_ok());
    }

    #[test]
    fn scramble_short_flags_parse() {
        let m = Cli::command().try_get_matches_from([
            "babbleon", "scramble", "-i", "in.py", "-o", "out.scr",
        ]);
        assert!(m.is_ok());
    }

    #[test]
    fn unscramble_with_input_and_output_paths_parses() {
        let m = Cli::command().try_get_matches_from([
            "babbleon",
            "unscramble",
            "--input",
            "in.scr",
            "--output",
            "out.py",
        ]);
        assert!(m.is_ok());
    }

    #[test]
    fn input_source_from_none_is_stdin() {
        assert!(matches!(super::input_source_from(None), InputSource::Stdin));
    }

    #[test]
    fn input_source_from_dash_is_stdin() {
        assert!(matches!(
            super::input_source_from(Some(PathBuf::from("-"))),
            InputSource::Stdin
        ));
    }

    #[test]
    fn input_source_from_path_is_file() {
        let s = super::input_source_from(Some(PathBuf::from("/tmp/x.py")));
        match s {
            InputSource::File(p) => assert_eq!(p, PathBuf::from("/tmp/x.py")),
            InputSource::Stdin => panic!("expected File"),
        }
    }

    #[test]
    fn output_sink_from_none_is_stdout() {
        assert!(matches!(super::output_sink_from(None), OutputSink::Stdout));
    }

    #[test]
    fn output_sink_from_dash_is_stdout() {
        assert!(matches!(
            super::output_sink_from(Some(PathBuf::from("-"))),
            OutputSink::Stdout
        ));
    }

    #[test]
    fn output_sink_from_path_is_file() {
        let s = super::output_sink_from(Some(PathBuf::from("/tmp/x.scr")));
        match s {
            OutputSink::File(p) => assert_eq!(p, PathBuf::from("/tmp/x.scr")),
            OutputSink::Stdout => panic!("expected File"),
        }
    }
}
