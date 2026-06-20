//! Process-wide hardening (lifecycle steps 3 and 7).
//!
//! # What this defeats
//!
//! Three classes of secret-leak to disk:
//!
//! - **Core dumps.**  A crash inside the launcher would otherwise
//!   write the launcher's address space (and any inherited heap
//!   from the calling shell) to a core file readable by the user.
//!   `PR_SET_DUMPABLE = 0` + `RLIMIT_CORE = 0` prevent it.
//! - **Swap pages.**  Kernel decisions about which pages to evict
//!   to swap are opaque to userspace.  `mlockall(MCL_CURRENT |
//!   MCL_FUTURE)` pins every page in RAM so secret-bearing pages
//!   cannot leak to disk.
//! - **Privilege re-acquisition by the child.**
//!   `PR_SET_NO_NEW_PRIVS = 1` makes setuid bits, file caps, and
//!   `AppArmor` profile transitions on subsequent `execve` no-ops.
//!   The child cannot gain capabilities the launcher dropped.
//!
//! # Mechanism
//!
//! All three are `prctl` / `setrlimit` / `mlockall` calls on the
//! calling process — no kernel resources allocated, no child
//! processes touched.  Idempotent.
//!
//! # Threat model boundaries
//!
//! - Defeats: secret bytes hitting disk via the documented kernel
//!   paths.
//! - Defeats: child privilege escalation across `execve`.
//! - Does NOT defeat: an attacker with kernel read primitives.
//!   `mlockall` keeps pages off swap; it does NOT make them
//!   unreadable by privileged kernel callers.

#![cfg(target_os = "linux")]

use nix::sys::mman::{mlockall, MlockAllFlags};
use nix::sys::resource::{setrlimit, Resource};

use crate::errors::{Error, Result};
use crate::syscall;

/// Step 3 — apply the secret-hygiene triad:
///
/// 1. `PR_SET_DUMPABLE = 0` — no core file.
/// 2. `RLIMIT_CORE = 0` — belt-and-suspenders against (1).
/// 3. `mlockall(MCL_CURRENT | MCL_FUTURE)` — refuse swap.
///
/// CAPABILITY for the `mlockall` call: `CAP_IPC_LOCK` if the
/// caller's `RLIMIT_MEMLOCK` is below the working set, else none.
/// The launcher's install-time file caps include `CAP_IPC_LOCK`
/// so production deployments always succeed; in container CI we
/// degrade gracefully (warn + continue) so the launcher is still
/// testable.
///
/// CAPABILITY for the other two: none.
///
/// # Errors
///
/// Returns [`Error::Hardening`] if `PR_SET_DUMPABLE` or
/// `RLIMIT_CORE` fail — those should not fail on any sane Linux
/// host and a failure indicates kernel-config anomaly worth
/// surfacing.
///
/// `mlockall` failure is downgraded to a `tracing::warn!` because
/// container hosts often legitimately deny `CAP_IPC_LOCK`.  An
/// operator who needs hard-guarantee no-swap must run with the
/// capability or accept the warning.
pub fn apply_secret_hygiene() -> Result<()> {
    syscall::prctl_set_dumpable_off()
        .map_err(|e| Error::Hardening(format!("PR_SET_DUMPABLE: {e}")))?;

    // RLIMIT_CORE = 0 — both soft and hard zero so the child can't
    // raise it back.
    setrlimit(Resource::RLIMIT_CORE, 0, 0)
        .map_err(|e| Error::Hardening(format!("RLIMIT_CORE: {e}")))?;

    // mlockall is best-effort.  Failure modes worth distinguishing:
    //   ENOMEM    — RLIMIT_MEMLOCK too low; tighten before retry.
    //   EPERM     — caller lacks CAP_IPC_LOCK; degrade in container.
    //   EINVAL    — caller passed wrong flags (compile-time bug).
    if let Err(e) = mlockall(MlockAllFlags::MCL_CURRENT | MlockAllFlags::MCL_FUTURE) {
        tracing::warn!(
            "mlockall failed ({e}); secret pages may be swappable. \
             Production install grants CAP_IPC_LOCK; container hosts \
             commonly deny it.  Continuing — operator's call.",
        );
    }

    // Discard caps on the upcoming setuid (step 9).  Default already
    // is "discard"; we set explicitly so a wrapper script that
    // turned KEEPCAPS on in our parent process doesn't leak in.
    syscall::prctl_set_keepcaps_off()
        .map_err(|e| Error::Hardening(format!("PR_SET_KEEPCAPS: {e}")))?;

    Ok(())
}

/// Step 7 — set `PR_SET_NO_NEW_PRIVS = 1`.
///
/// CAPABILITY: none.  Always allowed.
///
/// Must be called AFTER all bind-mounts and BEFORE seccomp install
/// (seccomp install otherwise requires `CAP_SYS_ADMIN`; with NNP
/// set, it does not).
///
/// # Errors
///
/// Returns [`Error::Hardening`] if `prctl` fails.  Should never
/// happen on a Linux kernel >= 3.5.
pub fn set_no_new_privs() -> Result<()> {
    syscall::prctl_set_no_new_privs()
        .map_err(|e| Error::Hardening(format!("PR_SET_NO_NEW_PRIVS: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_no_new_privs_succeeds_for_self() {
        // `PR_SET_NO_NEW_PRIVS` is monotonic — setting it stays
        // set across forks and execs.  The test process inherits
        // it for any subsequent test, which is fine: NNP doesn't
        // prevent anything Cargo's test runner does.
        set_no_new_privs().expect("PR_SET_NO_NEW_PRIVS=1 must succeed");
    }
}
