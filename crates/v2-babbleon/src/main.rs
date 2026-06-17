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
//! own address space.  Privileged operations (mounting, sealing the
//! vault) are dispatched to the daemon over a local Unix socket; this
//! process is a thin client.  As such, the CLI does not require
//! `forbid(unsafe_code)` to be a meaningful security claim — there is
//! no secret material to leak — but we keep the lint enabled for
//! discipline.
//!
//! Phase 1 ships the command surface and argument parsing; the actual
//! daemon-side wiring lands in phase 2 alongside
//! `babbleon-launch-untrusted`.  Until then, each subcommand returns
//! a clear "not yet implemented" stub so operator scripts can be
//! authored against the final surface.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use anyhow::Result;
use clap::{Parser, Subcommand};

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
    /// and writes the initial epoch mapping.  Run once per host.
    Init,

    /// Unlock the vault for the current session.  Prompts for the
    /// credential (passphrase, security key, or both depending on
    /// configuration).  On success, the daemon holds the epoch
    /// keys in mlock'd memory until session end.
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
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    install_tracing(cli.verbose);

    match cli.cmd {
        // Stubs until the daemon-side wiring lands in phase 2.  Each
        // returns an Err so a script that conditionally relies on the
        // operation having taken effect fails loudly rather than
        // silently no-op'ing.
        Cmd::Init => not_yet_implemented("init"),
        Cmd::Unlock => not_yet_implemented("unlock"),
        Cmd::RotateMapping => not_yet_implemented("rotate-mapping"),
        Cmd::Status => not_yet_implemented("status"),
        Cmd::MountScrambledView => not_yet_implemented("mount-scrambled-view"),
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

/// Phase-1 placeholder.  Returns Err so scripts surface the gap
/// loudly instead of silently succeeding.
fn not_yet_implemented(command: &str) -> Result<()> {
    anyhow::bail!(
        "`{command}` is not yet implemented in v2 phase 1; \
         see V2_PLAN.md for the phase roadmap",
    )
}

#[cfg(test)]
mod tests {
    use super::Cli;
    use clap::CommandFactory;

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
}
