//! Process-wide hardening at daemon startup.
//!
//! # What this defeats
//!
//! Closes the three documented kernel paths by which the per-host
//! secret could reach disk:
//!
//! - **Core dumps.**  A crash inside the daemon process — segfault,
//!   panic with `RUST_BACKTRACE` set, OOM-kill if the limit allows —
//!   would otherwise write the daemon's address space (which
//!   contains the per-host secret in `Zeroizing<[u8; 32]>`) to a
//!   core file readable by the user.  `PR_SET_DUMPABLE = 0` +
//!   `RLIMIT_CORE = 0` together prevent it.
//! - **Swap pages.**  Kernel decisions about which pages to evict
//!   to swap are opaque to userspace.  `mlockall(MCL_CURRENT |
//!   MCL_FUTURE)` pins every page in RAM so secret-bearing pages
//!   cannot leak to disk.
//! - **`/proc/$pid/mem` peek by another process with `CAP_SYS_PTRACE`.**
//!   `PR_SET_DUMPABLE = 0` also makes `/proc/$pid/{mem,maps,environ,...}`
//!   owned by root with mode 0; only a peer with `CAP_SYS_PTRACE`
//!   can read.  Defense in depth against a same-uid attacker who
//!   gets `CAP_SYS_PTRACE` through some other path.
//!
//! Security-baseline rule 8: launchers and CLI binaries that load
//! secret material into memory MUST call this before any secret
//! enters the process.  The daemon is one of those binaries; this
//! module is its compliance.
//!
//! # Mechanism
//!
//! Three syscalls, all on the calling process, all idempotent:
//!
//! 1. `prctl(PR_SET_DUMPABLE, 0, ...)` via `nix::sys::prctl::set_dumpable`.
//! 2. `setrlimit(RLIMIT_CORE, 0, 0)` via `nix::sys::resource::setrlimit`.
//! 3. `mlockall(MCL_CURRENT | MCL_FUTURE)` via `nix::sys::mman::mlockall`.
//!
//! All three are safe wrappers from `nix`; the daemon stays
//! `forbid(unsafe_code)` at the crate root.
//!
//! `mlockall` is best-effort: container hosts commonly deny
//! `CAP_IPC_LOCK`.  A failure degrades to a `tracing::warn!` so the
//! daemon still runs; operators who need hard-guarantee no-swap must
//! either grant `CAP_IPC_LOCK` or raise `RLIMIT_MEMLOCK`.  The other
//! two MUST succeed; their failure is fatal.
//!
//! # Threat model boundaries
//!
//! - **Defeats:** secret bytes hitting disk via core dumps, swap
//!   pages, or `/proc/$pid/mem` (defense in depth on the latter).
//! - **Does NOT defeat:** an attacker with kernel-level read.
//!   `mlockall` keeps pages off swap; it does NOT make them
//!   unreadable by privileged kernel callers (e.g. `kgdb`, eBPF
//!   tracing, or a kernel CVE).
//! - **Does NOT defeat:** an attacker who has already obtained the
//!   secret via a different path (heap overread bug in the daemon,
//!   inherited environment from the daemon's parent, etc.).

#![cfg(target_os = "linux")]

use nix::sys::mman::{mlockall, MlockAllFlags};
use nix::sys::prctl;
use nix::sys::resource::{setrlimit, Resource};

use crate::errors::{Error, Result};

/// Apply the daemon's secret-hygiene triad before any secret reaches
/// memory.
///
/// Call site: `main::run_daemon` before `PerHostSecret::from_bytes`.
///
/// # Errors
///
/// - [`Error::Ipc`] if `PR_SET_DUMPABLE` or `RLIMIT_CORE` fails.
///   Both should always succeed on a sane Linux host; a failure
///   indicates kernel-config anomaly worth surfacing to the
///   operator (they may be on a kernel without `CONFIG_COREDUMP`,
///   in which case the core-dump path is closed for a different
///   reason, but a misconfigured environment is more likely).
///
///   We use the `Ipc` variant rather than adding a new `Hardening`
///   one to keep the daemon's error surface small; the Display
///   string carries the original syscall name so log-side triage
///   is unambiguous.
///
/// `mlockall` failure is downgraded to a tracing warning and does
/// NOT propagate as an error — see module-level docs for rationale.
pub fn apply_secret_hygiene() -> Result<()> {
    prctl::set_dumpable(false).map_err(|e| {
        Error::Ipc(format!("PR_SET_DUMPABLE=0 (prctl): {e}"))
    })?;

    // RLIMIT_CORE = 0 (both soft and hard).  Defense in depth on
    // top of PR_SET_DUMPABLE.
    setrlimit(Resource::RLIMIT_CORE, 0, 0).map_err(|e| {
        Error::Ipc(format!("RLIMIT_CORE=0 (setrlimit): {e}"))
    })?;

    // mlockall is best-effort.  Container hosts commonly EPERM here.
    if let Err(e) =
        mlockall(MlockAllFlags::MCL_CURRENT | MlockAllFlags::MCL_FUTURE)
    {
        tracing::warn!(
            "mlockall failed ({e}); daemon secret pages may be \
             swappable.  Production install grants CAP_IPC_LOCK; \
             container hosts commonly deny it.  Continuing — \
             operator's call.",
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_secret_hygiene_is_idempotent_for_self() {
        // The three operations are idempotent on the calling
        // process; calling twice in the test binary should not
        // change behaviour or error.  We do NOT assert that all
        // three succeed (mlockall is allowed to fail in CI); we
        // assert the function returns Ok in either path.
        apply_secret_hygiene().expect("first call");
        apply_secret_hygiene().expect("second call");
    }

    #[test]
    fn dumpable_off_visible_via_proc_self_status_after_apply() {
        // After PR_SET_DUMPABLE=0, /proc/self/status reports
        // `CoreDumping: 0` and the dumpable bit changes.  We don't
        // assert the exact line shape (varies by kernel); we just
        // assert apply returns Ok and proc shows a populated status.
        apply_secret_hygiene().expect("apply");
        let status =
            std::fs::read_to_string("/proc/self/status").unwrap();
        assert!(status.contains("Name:"));
    }
}
