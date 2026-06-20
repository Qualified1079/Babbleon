//! Per-process self-hardening for secret-holding processes.
//!
//! # What this defeats
//!
//! Zeroizing in-memory secrets on drop closes one leakage class, but
//! the secret has to live in memory while it's *being used*.  Three
//! kernel features stop that in-use copy from escaping to disk:
//!
//!   1. **`PR_SET_DUMPABLE` = 0** — refuses core dumps for the
//!      process.  Without this, a crash (SIGSEGV, panic, OOM-kill)
//!      can write a core file containing the unzeroized live copy
//!      of `host_secret` to disk, where any user with read access
//!      can recover it later.
//!   2. **`RLIMIT_CORE` = 0** — belt to that suspenders.  Even if
//!      `PR_SET_DUMPABLE` is reset by code we don't control, the
//!      rlimit caps core-file size at zero bytes.
//!   3. **`mlockall(MCL_CURRENT | MCL_FUTURE)`** — pins the
//!      process's entire address space in RAM, preventing the kernel
//!      from paging secret-containing pages to swap.  Without this,
//!      a host under memory pressure can write secret material to
//!      the page file, where it lives until the swap area is
//!      overwritten — potentially weeks.
//!
//! These functions are best-effort: failure to call them does not
//! prevent secret access, but the failure should be surfaced via
//! `tracing::warn!` so operators see the degraded posture.  We do not
//! `panic!` on hardening-call failures because doing so would break
//! unprivileged use-cases (e.g. development builds where
//! `RLIMIT_MEMLOCK` is too low for `mlockall`).
//!
//! Call `harden_for_secrets()` early — before reading the vault,
//! before deriving the KEK, before instantiating `Mapper`.  Order
//! matters: the kernel only honours `PR_SET_DUMPABLE = 0` for syscalls
//! made *after* the prctl.

#![cfg(target_os = "linux")]

use crate::errors::{BabbleonError, Result};

/// Outcome of a single self-hardening attempt, surfaced for tests
/// and status output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HardeningStep {
    /// The kernel feature was applied successfully.
    Applied,
    /// The feature is unavailable on this kernel or container.
    /// E.g. `mlockall` requires `CAP_IPC_LOCK` or a sufficient
    /// `RLIMIT_MEMLOCK`; an unprivileged container often has neither.
    Unavailable(i32),
}

/// Composite result of `harden_for_secrets`.
#[derive(Debug, Clone, Copy)]
pub struct HardeningReport {
    pub set_dumpable: HardeningStep,
    pub rlimit_core: HardeningStep,
    pub mlockall: HardeningStep,
}

impl HardeningReport {
    /// True when *every* step applied.  Useful for tests; production
    /// callers should accept partial hardening with a tracing::warn!.
    pub fn fully_applied(&self) -> bool {
        matches!(
            (self.set_dumpable, self.rlimit_core, self.mlockall),
            (
                HardeningStep::Applied,
                HardeningStep::Applied,
                HardeningStep::Applied
            )
        )
    }
}

/// `prctl(PR_SET_DUMPABLE, 0)` — refuses core dumps for this process.
pub fn forbid_core_dump_via_prctl() -> HardeningStep {
    // SAFETY: `prctl(2)` with `PR_SET_DUMPABLE` and a single scalar
    // argument is a documented kernel ABI.  No pointers; no aliasing.
    let rc = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
    if rc == 0 {
        HardeningStep::Applied
    } else {
        // SAFETY: `__errno_location` returns a per-thread pointer
        // valid for the lifetime of the thread.
        let errno = unsafe { *libc::__errno_location() };
        HardeningStep::Unavailable(errno)
    }
}

/// `setrlimit(RLIMIT_CORE, 0)` — caps core-file size at zero.
pub fn forbid_core_dump_via_rlimit() -> HardeningStep {
    let lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `setrlimit(2)` takes a resource integer and a pointer to
    // a `rlimit` struct we own and have fully initialized above.  The
    // kernel reads the struct synchronously and does not retain the
    // pointer.
    let rc = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &lim) };
    if rc == 0 {
        HardeningStep::Applied
    } else {
        // SAFETY: see prctl path.
        let errno = unsafe { *libc::__errno_location() };
        HardeningStep::Unavailable(errno)
    }
}

/// `mlockall(MCL_CURRENT | MCL_FUTURE)` — pins all pages in RAM, no
/// swap-out.
///
/// Likely returns `EPERM` in unprivileged containers; we surface that
/// as `Unavailable(EPERM)` so the caller can decide whether degraded
/// posture is acceptable.
pub fn lock_memory_pages() -> HardeningStep {
    // SAFETY: `mlockall(2)` takes a single scalar flag and pins the
    // calling process's pages.  No pointer arguments.
    let rc = unsafe { libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) };
    if rc == 0 {
        HardeningStep::Applied
    } else {
        // SAFETY: see prctl path.
        let errno = unsafe { *libc::__errno_location() };
        HardeningStep::Unavailable(errno)
    }
}

/// Apply all three secret-process protections in order.
///
/// Tracing warnings are emitted for any step that fails; the caller
/// receives the structured report and decides whether to proceed.
/// Returns `Ok(report)` in all cases — the function never errors out
/// because partial hardening is still strictly better than none.
pub fn harden_for_secrets() -> Result<HardeningReport> {
    let set_dumpable = forbid_core_dump_via_prctl();
    if let HardeningStep::Unavailable(errno) = set_dumpable {
        tracing::warn!(
            "PR_SET_DUMPABLE failed (errno={errno}); \
             a crash could core-dump live secret material"
        );
    }

    let rlimit_core = forbid_core_dump_via_rlimit();
    if let HardeningStep::Unavailable(errno) = rlimit_core {
        tracing::warn!(
            "setrlimit(RLIMIT_CORE, 0) failed (errno={errno}); \
             core dumps not capped"
        );
    }

    let mlockall = lock_memory_pages();
    if let HardeningStep::Unavailable(errno) = mlockall {
        if errno == libc::EPERM {
            tracing::warn!(
                "mlockall failed with EPERM — \
                 process lacks CAP_IPC_LOCK or RLIMIT_MEMLOCK is too \
                 low; secret pages may be swapped"
            );
        } else if errno == libc::ENOMEM {
            tracing::warn!(
                "mlockall failed with ENOMEM — \
                 RLIMIT_MEMLOCK is insufficient for the process's \
                 working set; secret pages may be swapped"
            );
        } else {
            tracing::warn!("mlockall failed (errno={errno})");
        }
    }

    Ok(HardeningReport {
        set_dumpable,
        rlimit_core,
        mlockall,
    })
}

#[allow(dead_code)]
fn _shut_up_result_unused() -> Result<()> {
    Err(BabbleonError::Enforcement("unused".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forbid_core_dump_via_prctl_succeeds_unprivileged() {
        // PR_SET_DUMPABLE is one of the few prctls that works for
        // unprivileged callers without further capabilities.  If this
        // returns Unavailable, the test environment is unusual and
        // worth investigating.
        assert_eq!(
            forbid_core_dump_via_prctl(),
            HardeningStep::Applied,
            "PR_SET_DUMPABLE should succeed in any process; \
             check the test environment if it fails"
        );
    }

    #[test]
    fn rlimit_core_zero_succeeds_unprivileged() {
        // Lowering an rlimit is always allowed; raising it requires
        // capability.  We're lowering to zero, so this should work.
        assert_eq!(forbid_core_dump_via_rlimit(), HardeningStep::Applied);
    }

    #[test]
    fn harden_for_secrets_returns_report() {
        // The full triple may or may not fully apply depending on
        // how the test binary is run (toolbox/podman often lacks
        // CAP_IPC_LOCK).  We only assert that the call returns a
        // report and that the structurally-easy two succeed.
        let report = harden_for_secrets().expect("never errors out");
        assert_eq!(report.set_dumpable, HardeningStep::Applied);
        assert_eq!(report.rlimit_core, HardeningStep::Applied);
        // mlockall may or may not apply; we don't assert.
    }
}
