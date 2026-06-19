//! Lifecycle steps 4 + 5 — enter fresh mount + PID namespaces and
//! make the new mount tree private.
//!
//! # What this defeats
//!
//! - **Mount-leak to host.**  Without `MS_PRIVATE` propagation on
//!   `/`, the bind-mounts we install in step 6 propagate back to
//!   the host mount namespace, polluting it with scrambled-name
//!   stubs and (worse) potentially overlaying host binaries during
//!   our setup window.  Making the mount tree private confines
//!   every subsequent mount to this namespace.
//!
//! - **`/proc` leak across PID NS.**  Without the new PID namespace,
//!   the untrusted-tier child can see (and `kill(2)`) every other
//!   process on the host via `/proc/<pid>/`.  The PID NS gives the
//!   child a fresh PID tree where it can see only itself and its
//!   descendants.
//!
//! # Mechanism
//!
//! Two `nix`-wrapped syscalls:
//!
//! - `unshare(CLONE_NEWNS | CLONE_NEWPID)` — atomic; both new
//!   namespaces or neither.
//! - `mount("none", "/", "none", MS_PRIVATE | MS_REC, NULL)` —
//!   recursively detach the new mount tree from the host.
//!
//! Neither call writes to disk.  `nix`'s wrappers audit `unsafe`
//! internally so the launcher's `deny(unsafe_code)` is preserved.
//!
//! # Threat model boundaries
//!
//! - Defeats: mount propagation to host, PID-visibility leakage.
//! - Does NOT defeat: kernel bugs in the `unshare` or `mount`
//!   implementations themselves (kernel update cadence is
//!   operator responsibility).
//! - Does NOT defeat: an attacker who has already escaped the
//!   namespace via a different vector.

#![cfg(target_os = "linux")]

use std::path::Path;

use nix::mount::{mount, MsFlags};
use nix::sched::{unshare, CloneFlags};

use crate::errors::{Error, Result};

/// Step 4 — enter a fresh mount + PID namespace via `unshare(2)`.
///
/// CAPABILITY: `CAP_SYS_ADMIN` (required by `unshare(CLONE_NEWNS)`
/// AND `unshare(CLONE_NEWPID)` on traditional kernels; user
/// namespaces could relax this but v2 does NOT use user
/// namespaces — see `docs/v2/least-privilege.md`).
///
/// # Errors
///
/// Returns [`Error::Unshare`] if the kernel refuses (`EPERM` =
/// caller lacks `CAP_SYS_ADMIN`; `ENOSPC` = per-user namespace
/// limit; `ENOMEM` = kernel allocation failure).
pub fn enter_fresh_namespaces() -> Result<()> {
    // CAPABILITY: CAP_SYS_ADMIN required for both NEWNS and NEWPID.
    // Dropped at step 10 via bounding-set clear + setuid side effect.
    unshare(CloneFlags::CLONE_NEWNS | CloneFlags::CLONE_NEWPID)
        .map_err(|e| Error::Unshare(format!("unshare(NEWNS|NEWPID): {e}")))
}

/// Step 5 — recursively mark the new mount tree as `MS_PRIVATE` so
/// subsequent mounts do not propagate back to the host's mount NS.
///
/// CAPABILITY: `CAP_SYS_ADMIN` (mount(2) with MS_PRIVATE on /).
///
/// # Errors
///
/// Returns [`Error::Mount`] if the remount fails.  In practice this
/// only fails if step 4 was skipped (no fresh NS) or `/` is on a
/// kernel that refuses the propagation change — both indicate a
/// caller bug.
pub fn make_root_private() -> Result<()> {
    // CAPABILITY: CAP_SYS_ADMIN required for mount(2) with MS_PRIVATE
    // on the existing mount at /.  Dropped at step 10.
    mount(
        Some("none"),
        "/",
        None::<&Path>,
        MsFlags::MS_PRIVATE | MsFlags::MS_REC,
        None::<&Path>,
    )
    .map_err(|e| Error::Mount(format!("MS_PRIVATE|MS_REC on /: {e}")))
}
