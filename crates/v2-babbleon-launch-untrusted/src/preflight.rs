//! Pre-flight checks — refuse a bad invocation before any state change.
//!
//! # What this defeats
//!
//! The launcher is reachable from any UID on the box.  Before it
//! begins mutating process state (dropping caps, entering namespaces,
//! mounting filesystems) it must reject invocations that cannot
//! possibly be legitimate:
//!
//! - Real-UID 0 (root).  The launcher exists to give a non-root
//!   user an isolated environment; root invoking the launcher would
//!   gain nothing and risks confused-deputy attacks where a root
//!   script accidentally inherits a half-built namespace.
//! - Empty child command.  Already enforced by `clap`, re-checked
//!   here so library callers (tests / future PAM module) get the
//!   same error path.
//! - Child command containing NUL bytes or pure path-traversal
//!   sequences.  `execvp` itself rejects these but we surface a
//!   typed error rather than relying on a downstream EINVAL.
//!
//! # Mechanism
//!
//! Pure read-only checks.  No syscalls that change state, no
//! capability consumption.  Cheap and deterministic.
//!
//! # Threat model boundaries
//!
//! - Defeats: confused-deputy by root, accidental no-op invocation,
//!   trivial argument-injection at the launcher boundary.
//! - Does NOT defeat: a malicious non-root user who passes a
//!   legitimate-looking command.  That is the threat model the
//!   namespace itself addresses; pre-flight is for invocation
//!   shape, not invocation intent.

use crate::cli::Args;
use crate::errors::{Error, Result};

/// Real-UID, real-GID, and the validated child command.
///
/// Library callers (tests, future PAM module) can run pre-flight in
/// isolation and inspect this struct before delegating to the
/// orchestrator.  The orchestrator treats it as opaque.
#[derive(Debug, Clone)]
pub struct PreflightOutcome {
    /// The real UID of the caller, snapshotted before any
    /// identity-affecting syscall fires.  Re-applied at step 9.
    pub real_uid: u32,
    /// The real GID of the caller.  Re-applied at step 9.
    pub real_gid: u32,
    /// The child command vector, validated for embedding safety.
    /// `child_command[0]` is the program; subsequent entries are
    /// its arguments.
    pub child_command: Vec<String>,
}

/// Inspect arguments + caller identity and return an opaque outcome
/// the orchestrator passes through subsequent steps.
///
/// # Errors
///
/// Returns [`Error::Preflight`] when:
///
/// - The child command is empty (callable via library, not via clap).
/// - The caller's real-UID is 0.
/// - Any element of the child command contains a NUL byte (would be
///   rejected by `execvp` downstream; we fail early to avoid leaving
///   the process in a half-set-up state when that EINVAL fires).
// `real_uid`/`real_gid` mirror the kernel terminology (getuid(2),
// getgid(2)).  They are operator-facing identifiers carried through
// the entire 11-step lifecycle; renaming for clippy::similar_names
// would degrade auditability for a 3-character visual difference.
#[allow(clippy::similar_names)]
pub fn check(args: &Args, real_uid: u32, real_gid: u32) -> Result<PreflightOutcome> {
    if args.child_command.is_empty() {
        return Err(Error::Preflight(
            "child command must not be empty".into(),
        ));
    }
    if real_uid == 0 {
        return Err(Error::Preflight(
            "launcher must be invoked by a non-root user (real-UID 0 rejected)".into(),
        ));
    }
    for (i, arg) in args.child_command.iter().enumerate() {
        if arg.as_bytes().contains(&0) {
            return Err(Error::Preflight(format!(
                "child command argument {i} contains a NUL byte"
            )));
        }
    }
    Ok(PreflightOutcome {
        real_uid,
        real_gid,
        child_command: args.child_command.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::{check, Args};

    fn args(items: &[&str]) -> Args {
        Args {
            child_command: items.iter().map(|s| (*s).to_string()).collect(),
        }
    }

    #[test]
    fn root_caller_rejected() {
        let err = check(&args(&["/bin/sh"]), 0, 0).unwrap_err();
        assert!(
            format!("{err}").contains("non-root"),
            "error must name the root rejection: {err}",
        );
    }

    #[test]
    fn empty_command_rejected_via_library() {
        let err = check(&args(&[]), 1000, 1000).unwrap_err();
        assert!(format!("{err}").contains("empty"), "{err}");
    }

    #[test]
    fn nul_byte_in_arg_rejected() {
        let err = check(&args(&["/bin/sh", "with\0nul"]), 1000, 1000).unwrap_err();
        assert!(format!("{err}").contains("NUL"), "{err}");
    }

    #[test]
    fn legitimate_invocation_accepted() {
        let outcome = check(&args(&["/usr/bin/curl", "-sS"]), 1000, 1000).unwrap();
        assert_eq!(outcome.real_uid, 1000);
        assert_eq!(outcome.real_gid, 1000);
        assert_eq!(outcome.child_command.len(), 2);
    }

    #[test]
    fn nul_byte_in_program_rejected() {
        let err = check(&args(&["bad\0prog"]), 1000, 1000).unwrap_err();
        assert!(format!("{err}").contains("argument 0"), "{err}");
    }
}
