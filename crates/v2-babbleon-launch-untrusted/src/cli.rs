//! Argument parsing for the launcher binary.
//!
//! # Infrastructure module
//!
//! The launcher takes one mandatory argument — the command to
//! execute inside the established untrusted-tier environment —
//! plus its arguments.  No flags currently; the configuration
//! (scrambled view paths, tracked-tool list, wordlist root) lives
//! on disk under `/run/babbleon/` and is read at lifecycle step 6.
//!
//! This module exists primarily to anchor the help text the
//! operator sees on a bare `babbleon-launch-untrusted` invocation,
//! and to validate that the caller passed AT LEAST one positional
//! argument before the orchestrator drops any capabilities — a
//! "no-args" failure should not leave the process half-set-up.

use clap::Parser;

/// Parsed CLI input.
///
/// `child_command[0]` is the program to execute; subsequent entries
/// are its arguments.  Both are passed through to `execvp` verbatim.
#[derive(Debug, Clone, Parser)]
#[command(
    name = "babbleon-launch-untrusted",
    bin_name = "babbleon-launch-untrusted",
    version,
    about = "Establish the untrusted-tier execution environment and exec a child command.",
    long_about = "Babbleon v2 untrusted-tier launcher.

Establishes a fresh mount + PID namespace, materializes the scrambled
view via bind mounts, applies a seccomp deny-list, drops to the real
user, and execs the requested command inside that environment.

Installed with file capabilities (cap_sys_admin, cap_setuid, cap_setgid,
cap_ipc_lock), NOT setuid-root.  See docs/v2/least-privilege.md.",
    disable_help_subcommand = true,
    trailing_var_arg = true,
    allow_hyphen_values = true,
)]
pub struct Args {
    /// The child command and its arguments.  Required — at least
    /// one element.  Passed to `execvp(child_command[0],
    /// child_command)`.
    #[arg(
        required = true,
        num_args = 1..,
        value_name = "COMMAND [ARGS...]",
    )]
    pub child_command: Vec<String>,
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
    fn empty_command_is_rejected() {
        let result = Args::try_parse_from(["babbleon-launch-untrusted"]);
        assert!(
            result.is_err(),
            "missing command must be a parse error, got {result:?}"
        );
    }

    #[test]
    fn single_command_parses() {
        let args = Args::try_parse_from(["babbleon-launch-untrusted", "/bin/bash"]).unwrap();
        assert_eq!(args.child_command, vec!["/bin/bash".to_string()]);
    }

    #[test]
    fn command_with_args_parses() {
        let args = Args::try_parse_from([
            "babbleon-launch-untrusted",
            "/usr/bin/curl",
            "-sS",
            "https://example.com",
        ])
        .unwrap();
        assert_eq!(
            args.child_command,
            vec![
                "/usr/bin/curl".to_string(),
                "-sS".to_string(),
                "https://example.com".to_string(),
            ]
        );
    }

    #[test]
    fn hyphen_args_pass_through_to_child() {
        let args = Args::try_parse_from(["babbleon-launch-untrusted", "ls", "--", "-la"]).unwrap();
        assert!(
            args.child_command.contains(&"ls".to_string()),
            "child command must include `ls`: {:?}",
            args.child_command
        );
        assert!(
            args.child_command.contains(&"-la".to_string()),
            "child command must include `-la`: {:?}",
            args.child_command
        );
    }
}
