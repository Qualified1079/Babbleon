//! Argument parsing for the launcher binary.
//!
//! # Infrastructure module
//!
//! The launcher takes one mandatory positional — the command to
//! execute inside the established untrusted-tier environment —
//! plus its arguments.  Two optional flags select the source of
//! the per-epoch activated table (see
//! [`crate::activated_table_input`]):
//!
//! - `--activated-table-fd N`: read the JSONL from inherited fd N.
//!   The daemon uses this to pass the table without it touching
//!   the filesystem.
//! - `--activated-table-path P`: read the JSONL from file P.  Used
//!   by the rooted-test harness and by operators who want to drive
//!   the launcher without a daemon (e.g. CI smoke tests).
//!
//! If neither flag is given, the launcher establishes the
//! scrambled-view tmpfs and exec()s the child with NO bind-mounts
//! — useful for namespace+caps+seccomp smoke testing, NOT a
//! functional obfuscation deployment.

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
    /// File descriptor to read the activated-table JSONL from.
    /// Mutually exclusive with `--activated-table-path`.  The daemon
    /// passes the table this way so it never touches the launcher's
    /// filesystem view.
    #[arg(long = "activated-table-fd", value_name = "FD", conflicts_with = "activated_table_path")]
    pub activated_table_fd: Option<i32>,

    /// Path to a JSONL file holding the activated table.  Mutually
    /// exclusive with `--activated-table-fd`.  Intended for the
    /// rooted-test harness and for daemonless smoke tests.
    #[arg(long = "activated-table-path", value_name = "PATH")]
    pub activated_table_path: Option<std::path::PathBuf>,

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
    fn activated_table_path_flag_parses() {
        let args = Args::try_parse_from([
            "babbleon-launch-untrusted",
            "--activated-table-path",
            "/tmp/table.jsonl",
            "/bin/bash",
        ])
        .unwrap();
        assert_eq!(
            args.activated_table_path,
            Some(std::path::PathBuf::from("/tmp/table.jsonl"))
        );
        assert!(args.activated_table_fd.is_none());
    }

    #[test]
    fn activated_table_fd_flag_parses() {
        let args = Args::try_parse_from([
            "babbleon-launch-untrusted",
            "--activated-table-fd",
            "7",
            "/bin/bash",
        ])
        .unwrap();
        assert_eq!(args.activated_table_fd, Some(7));
        assert!(args.activated_table_path.is_none());
    }

    #[test]
    fn activated_table_fd_and_path_are_mutually_exclusive() {
        let result = Args::try_parse_from([
            "babbleon-launch-untrusted",
            "--activated-table-fd",
            "7",
            "--activated-table-path",
            "/tmp/table.jsonl",
            "/bin/bash",
        ]);
        assert!(result.is_err(), "both flags together must be rejected");
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
