//! Lifecycle step 9 — drop back to the invoking user's UID/GID.
//!
//! # What this defeats
//!
//! By step 9 the launcher has completed every privileged operation
//! (namespace setup, mounts, seccomp install).  Holding root euid
//! into the child would mean the child inherits the working caps;
//! `setuid(real_uid)` paired with `PR_SET_KEEPCAPS = 0` (set in
//! step 3) clears the effective capability set as a kernel side
//! effect of changing UID.
//!
//! # Mechanism
//!
//! Three syscalls, fixed order so an attacker observing partial
//! failure cannot exploit the intermediate state:
//!
//! 1. `setgroups(&[])` — drop every supplementary group.  Any
//!    group access the launcher inherited from PAM session-open
//!    is discharged.
//! 2. `setgid(real_gid)` — switch primary group.
//! 3. `setuid(real_uid)` — switch UID.  Last because the kernel
//!    refuses subsequent `setgid` if the UID change cleared
//!    `CAP_SETGID`.
//!
//! # Threat model boundaries
//!
//! - Defeats: child inheriting capabilities or root euid.
//! - Defeats: child inheriting unintended group memberships.
//! - Does NOT defeat: the real-UID being a privileged user (root
//!   invoking the launcher is rejected at pre-flight).

#![cfg(target_os = "linux")]

use nix::unistd::{setgid, setgroups, setuid, Gid, Uid};

use crate::errors::{Error, Result};

/// Step 9 — drop supplementary groups, GID, and UID to the caller's
/// real identity.
///
/// CAPABILITY: `CAP_SETGID` for `setgroups` + `setgid`;
/// `CAP_SETUID` for `setuid`.  Both dropped at step 10.
///
/// # Errors
///
/// Returns [`Error::Identity`] if any of the three syscalls fail.
/// `setgroups` failure usually indicates a kernel `userns` config
/// mismatch; `setuid` / `setgid` failure indicates the working caps
/// were dropped too eagerly (caller error).
// See preflight::check for the rationale: `real_uid`/`real_gid` are
// kernel terminology preserved across the entire lifecycle.
#[allow(clippy::similar_names)]
pub fn drop_to_real_user(real_uid: u32, real_gid: u32) -> Result<()> {
    // CAPABILITY: CAP_SETGID required for setgroups when removing
    // supplementary groups.  Dropped at step 10.
    setgroups(&[]).map_err(|e| Error::Identity(format!("setgroups([]): {e}")))?;

    // CAPABILITY: CAP_SETGID required for setgid to a different GID.
    setgid(Gid::from_raw(real_gid))
        .map_err(|e| Error::Identity(format!("setgid({real_gid}): {e}")))?;

    // CAPABILITY: CAP_SETUID required for setuid to a different UID.
    // Side effect with PR_SET_KEEPCAPS=0: effective cap set is
    // cleared as the UID changes.  This is the actual privilege
    // discharge.
    setuid(Uid::from_raw(real_uid))
        .map_err(|e| Error::Identity(format!("setuid({real_uid}): {e}")))?;

    Ok(())
}
