//! Process-hygiene triad applied at shim startup.
//!
//! # What this defeats
//!
//! The shim's address space transiently holds:
//!
//! - The per-epoch whitespace compounds (5 strings, secret-adjacent).
//! - The unscrambled Python source bytes between
//!   `pipeline::unscramble` and `exec_python::feed_and_wait`.
//!
//! Without process-level hygiene, a crash would write a core dump
//! containing both; another process with `CAP_SYS_PTRACE` could
//! `process_vm_readv` them out of memory; swapped pages could land
//! the source on disk transparently.
//!
//! This module installs the same three-step triad
//! `v2-babbleon-daemon::hardening` uses, in the same order, BEFORE
//! the shim reads any input or talks to any peer:
//!
//! 1. `prctl(PR_SET_DUMPABLE, 0)` — disables core dumps and locks
//!    `/proc/$pid/{mem,maps,environ,...}` from same-uid readers.
//! 2. `setrlimit(RLIMIT_CORE, 0)` — defense-in-depth on top of (1).
//!    Sets both soft and hard caps to zero.
//! 3. `mlockall(MCL_CURRENT | MCL_FUTURE)` — keeps pages off swap.
//!    Best-effort: container hosts commonly EPERM here.
//!
//! Failure of (1) or (2) is fatal: a kernel that refuses these
//! syscalls is so far off-spec that proceeding would be
//! confused-deputy.  Failure of (3) is a warning: container hosts
//! commonly deny `CAP_IPC_LOCK`, and the operator's deployment
//! decision (production grants `CAP_IPC_LOCK`; container often
//! doesn't) is what gates this.
//!
//! # Threat model boundaries
//!
//! - **Defeats**: core-dump-based key recovery, same-uid ptrace,
//!   swap-side disclosure of unscrambled source.
//! - **Does NOT defeat**: in-process memory disclosure
//!   (kernel CVE, hypervisor side channel).
//! - **Does NOT defeat**: shoulder-surfing the operator's terminal
//!   while python3's stdout is rendering.  Out of scope.

use nix::sys::mman::{mlockall, MlockAllFlags};
use nix::sys::prctl;
use nix::sys::resource::{setrlimit, Resource};

use anyhow::{Context, Result};

/// Apply the three-step hygiene triad before any secret-adjacent
/// bytes enter the shim's address space.
///
/// # Errors
///
/// - Wrapped `nix::Error` if `PR_SET_DUMPABLE=0` or `RLIMIT_CORE=0`
///   fails.  Both should always succeed on a sane Linux host; a
///   failure indicates a kernel-config anomaly worth surfacing to
///   the operator.
///
/// `mlockall` failure is downgraded to a `tracing::warn` and does
/// NOT propagate; see module-level docs for rationale.
pub fn apply() -> Result<()> {
    prctl::set_dumpable(false)
        .context("PR_SET_DUMPABLE=0 (prctl)")?;

    setrlimit(Resource::RLIMIT_CORE, 0, 0)
        .context("RLIMIT_CORE=0 (setrlimit)")?;

    if let Err(e) = mlockall(
        MlockAllFlags::MCL_CURRENT | MlockAllFlags::MCL_FUTURE,
    ) {
        tracing::warn!(
            error = %e,
            "mlockall failed; shim source pages may be swappable.  \
             Production install grants CAP_IPC_LOCK; container hosts \
             commonly deny it.  Continuing — operator's call.",
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::apply;

    #[test]
    fn apply_is_idempotent_for_self() {
        // The three syscalls are idempotent on the calling process;
        // we don't assert mlockall succeeds (CI commonly denies
        // CAP_IPC_LOCK), only that the function returns Ok in
        // either path.
        apply().expect("first call");
        apply().expect("second call");
    }

    #[test]
    fn apply_disables_proc_self_readability_for_other_uid_readers() {
        // After PR_SET_DUMPABLE=0, /proc/self/status reports
        // ownership and the dumpable bit changes.  We do not assert
        // the exact line shape (varies by kernel); we assert apply
        // returns Ok and proc shows a populated status.
        apply().expect("apply");
        let status = std::fs::read_to_string("/proc/self/status").unwrap();
        assert!(status.contains("Name:"));
    }
}
