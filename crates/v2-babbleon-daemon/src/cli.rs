//! Daemon CLI surface.
//!
//! # Infrastructure module
//!
//! The daemon binary supports two operating modes:
//!
//! - **Long-running mode** (`run`): accept connections on the
//!   socket and serve `unlock` / `request-activated-table` /
//!   `rotate-mapping` / `status` requests.  This is what a
//!   systemd unit invokes.
//! - **One-shot subcommands**: convenience wrappers around the
//!   socket calls for operator use from a shell.  Each opens the
//!   socket, sends one request, prints the response, exits.
//!
//! In phase 2 only the surface is filed; each command returns a
//! "not yet implemented" error so an operator who wires up the
//! daemon prematurely gets a clean failure rather than a silent
//! no-op.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// Parsed CLI input.
#[derive(Debug, Parser)]
#[command(
    name = "babbleon-daemon",
    bin_name = "babbleon-daemon",
    version,
    about = "Babbleon v2 daemon: holds the per-host secret; ships activated tables to the launcher.",
    long_about = "Babbleon v2 daemon.

Runs as a dedicated UID with no capabilities (CAP_IPC_LOCK only,
for mlockall).  Holds the per-host secret in memory after unlock;
serves activated tables to babbleon-launch-untrusted over a Unix
socket.  Never touches the network.

See docs/v2/least-privilege.md for the full capability envelope
and docs/v2/threat-model.md for the threat model.",
    disable_help_subcommand = true,
)]
pub struct Args {
    /// Verbosity.  `-v` enables INFO; `-vv` enables DEBUG.
    #[arg(short = 'v', long = "verbose", action = clap::ArgAction::Count, global = true)]
    pub verbose: u8,

    /// Override the daemon's socket path.  Useful for tests; in
    /// production the default at `/run/babbleon/daemon.sock` is
    /// what `babbleon-launch-untrusted` and `babbleon-cli` connect
    /// to.
    #[arg(long = "socket", value_name = "PATH", global = true)]
    pub socket: Option<std::path::PathBuf>,

    /// Subcommand to run.
    #[command(subcommand)]
    pub cmd: Cmd,
}

/// Subcommands.
#[derive(Debug, Subcommand)]
pub enum Cmd {
    /// Run the daemon's long-running event loop.  Accepts
    /// connections on `--socket` (default
    /// `/run/babbleon/daemon.sock`) and serves activated-table
    /// requests until SIGTERM.
    Run(RunArgs),

    /// One-shot: connect to the running daemon and request an
    /// activated table for the current epoch.  Prints the JSONL to
    /// stdout.  Used by the rooted-test harness; operators
    /// normally don't run this directly.
    EmitActivatedTable,

    /// Read-only: print the daemon's current state (epoch number,
    /// tracked-tool count, last rotation time, vault-locked status).
    Status,

    /// Bump the epoch and refresh the activated-table cache.
    /// Triggers tripwire firing on every previous-epoch scrambled
    /// name.
    #[command(name = "rotate-mapping", alias = "rm")]
    RotateMapping,
}

/// Arguments to the long-running `run` subcommand.
///
/// Phase 2 ships without a real vault unlock; the daemon refuses to
/// start unless `--insecure-stub-secret` is passed explicitly.  The
/// flag documents itself as development-only in `--help`.
#[derive(Debug, clap::Args)]
pub struct RunArgs {
    /// Wrapper directory the daemon emits paths under in the
    /// activated table.  Must be absolute.
    #[arg(long = "wrapper-dir", value_name = "PATH")]
    pub wrapper_dir: std::path::PathBuf,

    /// Canonical tool name to track, optionally with an explicit
    /// real-binary path: `NAME` or `NAME=PATH`.  Without `=PATH`
    /// the daemon resolves the name via `$PATH` at startup; an
    /// unresolved name is a fatal startup error.  Repeat for each
    /// tool; the activated table will contain one entry per flag.
    #[arg(long = "tracked-tool", value_name = "NAME[=PATH]", value_parser = parse_tracked_tool)]
    pub tracked_tools: Vec<ParsedTrackedTool>,

    /// Use a hardcoded development secret instead of loading from
    /// the vault.  PHASE 2 STUB — required while real vault unlock
    /// is not yet wired.  Refuses to start without this flag.
    #[arg(long = "insecure-stub-secret")]
    pub insecure_stub_secret: bool,
}

/// One parsed `--tracked-tool` value.  Real-binary path is `Some`
/// iff the operator passed `NAME=PATH`; `None` means "resolve via
/// $PATH at startup" (deferred to `main.rs`, not done here so the
/// CLI layer stays free of filesystem I/O).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedTrackedTool {
    /// Canonical tool name (left of `=`, or the whole value).
    pub name: String,
    /// Explicit real-binary path (right of `=`), if supplied.
    pub real_path: Option<PathBuf>,
}

fn parse_tracked_tool(input: &str) -> std::result::Result<ParsedTrackedTool, String> {
    if input.is_empty() {
        return Err("tracked-tool value is empty".into());
    }
    if let Some((name, path)) = input.split_once('=') {
        if name.is_empty() {
            return Err("tracked-tool name (left of '=') is empty".into());
        }
        if path.is_empty() {
            return Err(format!("tracked-tool {name:?}: path (right of '=') is empty"));
        }
        let pb = PathBuf::from(path);
        if !pb.is_absolute() {
            return Err(format!(
                "tracked-tool {name:?}: explicit path {path:?} must be absolute",
            ));
        }
        return Ok(ParsedTrackedTool {
            name: name.to_string(),
            real_path: Some(pb),
        });
    }
    Ok(ParsedTrackedTool {
        name: input.to_string(),
        real_path: None,
    })
}

#[cfg(test)]
mod tests {
    use super::Args;
    use clap::{CommandFactory, Parser};

    #[test]
    fn clap_definition_is_valid() {
        Args::command().debug_assert();
    }

    #[test]
    fn run_subcommand_parses_with_required_flags() {
        let args = Args::try_parse_from([
            "babbleon-daemon",
            "run",
            "--wrapper-dir",
            "/wrappers",
            "--insecure-stub-secret",
        ])
        .unwrap();
        match args.cmd {
            super::Cmd::Run(r) => {
                assert_eq!(
                    r.wrapper_dir,
                    std::path::PathBuf::from("/wrappers")
                );
                assert!(r.insecure_stub_secret);
                assert!(r.tracked_tools.is_empty());
            }
            other => panic!("expected Run, got {other:?}"),
        }
    }

    #[test]
    fn run_subcommand_accepts_repeated_tracked_tool() {
        let args = Args::try_parse_from([
            "babbleon-daemon",
            "run",
            "--wrapper-dir",
            "/w",
            "--tracked-tool",
            "curl",
            "--tracked-tool",
            "ssh",
            "--insecure-stub-secret",
        ])
        .unwrap();
        match args.cmd {
            super::Cmd::Run(r) => {
                let names: Vec<&str> =
                    r.tracked_tools.iter().map(|t| t.name.as_str()).collect();
                assert_eq!(names, vec!["curl", "ssh"]);
                assert!(r.tracked_tools.iter().all(|t| t.real_path.is_none()));
            }
            other => panic!("expected Run, got {other:?}"),
        }
    }

    #[test]
    fn tracked_tool_accepts_name_equals_path_form() {
        let args = Args::try_parse_from([
            "babbleon-daemon",
            "run",
            "--wrapper-dir",
            "/w",
            "--tracked-tool",
            "curl=/opt/bin/curl",
            "--insecure-stub-secret",
        ])
        .unwrap();
        match args.cmd {
            super::Cmd::Run(r) => {
                assert_eq!(r.tracked_tools.len(), 1);
                assert_eq!(r.tracked_tools[0].name, "curl");
                assert_eq!(
                    r.tracked_tools[0].real_path,
                    Some(std::path::PathBuf::from("/opt/bin/curl")),
                );
            }
            other => panic!("expected Run, got {other:?}"),
        }
    }

    #[test]
    fn tracked_tool_rejects_relative_explicit_path() {
        let result = Args::try_parse_from([
            "babbleon-daemon",
            "run",
            "--wrapper-dir",
            "/w",
            "--tracked-tool",
            "curl=bin/curl",
            "--insecure-stub-secret",
        ]);
        assert!(result.is_err());
    }

    #[test]
    fn tracked_tool_rejects_empty_path() {
        let result = Args::try_parse_from([
            "babbleon-daemon",
            "run",
            "--wrapper-dir",
            "/w",
            "--tracked-tool",
            "curl=",
            "--insecure-stub-secret",
        ]);
        assert!(result.is_err());
    }

    #[test]
    fn tracked_tool_rejects_empty_name() {
        let result = Args::try_parse_from([
            "babbleon-daemon",
            "run",
            "--wrapper-dir",
            "/w",
            "--tracked-tool",
            "=/opt/bin/curl",
            "--insecure-stub-secret",
        ]);
        assert!(result.is_err());
    }

    #[test]
    fn run_subcommand_requires_wrapper_dir() {
        let result = Args::try_parse_from([
            "babbleon-daemon",
            "run",
            "--insecure-stub-secret",
        ]);
        assert!(
            result.is_err(),
            "missing --wrapper-dir should be a parse error"
        );
    }

    #[test]
    fn status_subcommand_parses() {
        let args =
            Args::try_parse_from(["babbleon-daemon", "status"]).unwrap();
        assert!(matches!(args.cmd, super::Cmd::Status));
    }

    #[test]
    fn rotate_mapping_alias_rm_routes_to_rotate_mapping() {
        let args = Args::try_parse_from(["babbleon-daemon", "rm"]).unwrap();
        assert!(matches!(args.cmd, super::Cmd::RotateMapping));
    }

    #[test]
    fn socket_override_parses_before_subcommand() {
        let args = Args::try_parse_from([
            "babbleon-daemon",
            "--socket",
            "/tmp/test.sock",
            "status",
        ])
        .unwrap();
        assert_eq!(
            args.socket,
            Some(std::path::PathBuf::from("/tmp/test.sock"))
        );
    }
}
