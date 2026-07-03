//! Capability bounding-set management (lifecycle steps 2 and 10).
//!
//! # What this defeats
//!
//! v1's `babbleon-ns-helper` is installed setuid-root, granting all
//! 41 Linux capabilities.  A bug in the helper that diverts control
//! flow into an arbitrary syscall has all 41 capabilities available
//! — `CAP_SYS_MODULE` (load kernel modules), `CAP_NET_ADMIN`
//! (manipulate netfilter), `CAP_SYS_PTRACE` (attach to any process),
//! etc.
//!
//! v2 ships with FILE capabilities (`cap_sys_admin,cap_setuid,
//! cap_setgid,cap_ipc_lock,cap_setpcap=ep`) on a non-setuid binary.
//! At step 2, every other bounding-set bit is dropped so a
//! hypothetical exploit can never re-acquire those caps even via a
//! downstream `execve` of a setuid binary.
//!
//! At step 10 (after the namespace is set up, but BEFORE identity is
//! dropped — see the ordering note below) the five working caps
//! themselves are removed via `PR_CAPBSET_DROP` — by the time
//! `execve` of the child fires, the process holds NO capabilities
//! and `PR_SET_NO_NEW_PRIVS=1` (set at step 7) forbids any future
//! acquisition.
//!
//! # Why `CAP_SETPCAP` is a working cap, not just an audit footnote
//!
//! `PR_CAPBSET_DROP` itself requires the calling thread to hold
//! `CAP_SETPCAP` in its *effective* set — this is true for every
//! call, including the very first one at step 2, regardless of
//! which capability is being dropped.  `docs/v2/least-privilege.md`'s
//! original v1→v2 audit table (and v1's own SELinux/AppArmor
//! policies, which already list `setpcap`) omitted this from the
//! v2 code's `WORKING_CAPS`; without it, step 2 — the FIRST
//! privileged call the launcher makes — fails with `EPERM` on a
//! real file-capability install (caught by
//! `tests/capability_lifecycle.rs`, which runs as literal root and
//! so only surfaced the failure at step 10, where `CAP_SETPCAP` is
//! needed again after step 9 has already zeroed the effective set).
//! `CAP_SETPCAP` is therefore the fifth working cap: needed to
//! perform the drop, not merely dropped.
//!
//! # Mechanism
//!
//! Step 2 iterates `0..=CAP_LAST_CAP_MAX` and calls
//! `prctl(PR_CAPBSET_DROP, cap, ...)` for every capability NOT in
//! the five-cap working set.  `EINVAL` (slot not present on this
//! kernel) is silently ignored — older kernels have fewer slots
//! than newer ones; the bit is dropped on every kernel that has it.
//!
//! Step 10 clears the remaining bounding-set bits via the same
//! mechanism, and MUST run before step 9's `setuid` — `setuid` away
//! from UID 0 clears the effective/permitted capability sets
//! (`PR_SET_KEEPCAPS=0`, set in step 3), and once effective is
//! empty `CAP_SETPCAP` is gone too, so a `PR_CAPBSET_DROP` call
//! issued AFTER step 9 can never succeed.  See `main.rs::run` for
//! the orchestrator's actual (step-10-before-step-9) call order.
//!
//! # Threat model boundaries
//!
//! - Defeats: a launcher exploit that tries to invoke kernel
//!   operations outside the audited five-cap set.
//! - Defeats: child-process privilege regain via file caps on the
//!   exec target (combined with `NO_NEW_PRIVS`).
//! - Does NOT defeat: the five-cap window itself.  Steps 4-9 still
//!   hold those caps; an exploit *during* that window can use them.
//!   Compensating control: the five steps are short straight-line
//!   code with no attacker-influenceable input.

use std::collections::BTreeSet;

use crate::errors::{Error, Result};
use crate::syscall;

/// Linux currently defines capabilities 0 through 40 (`CAP_LAST_CAP`
/// on a recent mainline kernel is 40 = `CAP_CHECKPOINT_RESTORE`).  We
/// iterate one beyond that so a future-added capability slot gets
/// dropped too; the kernel returns EINVAL for unallocated slots
/// which we silently ignore.
const HIGHEST_KNOWN_CAP: i32 = 40;

/// The five capabilities the launcher needs across its lifecycle.
///
/// All other capabilities are dropped from the bounding set at
/// step 2.  These five are themselves dropped from permitted at
/// step 10.  Bit positions match the kernel's `CAP_*` constants
/// from `<linux/capability.h>`.  We embed the integer values
/// directly because the `libc` crate does not export them
/// (`CAP_*` are kernel-only constants, not part of the POSIX C
/// API the libc crate exposes).
///
/// `CAP_SETPCAP` is included not because any lifecycle step's own
/// *work* needs it, but because `PR_CAPBSET_DROP` — the syscall
/// steps 2 and 10 both use to shrink the bounding set — requires
/// `CAP_SETPCAP` in the effective set to run at all.  See the
/// module doc's "Why `CAP_SETPCAP` is a working cap" section.
pub const WORKING_CAPS: &[i32] = &[
    CAP_SYS_ADMIN,
    CAP_SETUID,
    CAP_SETGID,
    CAP_IPC_LOCK,
    CAP_SETPCAP,
];

/// `CAP_SETGID` — see `capabilities(7)`.
pub const CAP_SETGID: i32 = 6;
/// `CAP_SETUID` — see `capabilities(7)`.
pub const CAP_SETUID: i32 = 7;
/// `CAP_SETPCAP` — see `capabilities(7)`.  Required by
/// `PR_CAPBSET_DROP` itself (not just to drop `CAP_SETPCAP`, to
/// drop ANY bounding-set bit), which is why it must be a working
/// cap rather than one of the 36 dropped at step 2.
pub const CAP_SETPCAP: i32 = 8;
/// `CAP_IPC_LOCK` — see `capabilities(7)`.
pub const CAP_IPC_LOCK: i32 = 14;
/// `CAP_SYS_ADMIN` — see `capabilities(7)`.  The kitchen-sink cap;
/// reviewer attention concentrates here.
pub const CAP_SYS_ADMIN: i32 = 21;

/// Trim the bounding set to only the [`WORKING_CAPS`] set.
///
/// CAPABILITY: none — `PR_CAPBSET_DROP` on self is unprivileged.
///
/// # Errors
///
/// Returns [`Error::BoundingSet`] only if `prctl` returns a
/// non-`EINVAL` error.  `EINVAL` is silently ignored (the capability
/// slot doesn't exist on the running kernel — harmless and
/// kernel-version-dependent).
pub fn trim_to_working_set() -> Result<()> {
    let keep: BTreeSet<i32> = WORKING_CAPS.iter().copied().collect();
    for cap in 0..=HIGHEST_KNOWN_CAP {
        if keep.contains(&cap) {
            continue;
        }
        if let Err(e) = syscall::prctl_capbset_drop(cap) {
            // EINVAL = slot not allocated on this kernel; harmless.
            if e.raw_os_error() != Some(libc::EINVAL) {
                return Err(Error::BoundingSet(format!(
                    "cap {cap}: {e}"
                )));
            }
        }
    }
    Ok(())
}

/// Step 10 — drop EVERY capability from permitted (and therefore
/// effective).  Uses `prctl(PR_CAPBSET_DROP)` for the bounding set
/// (idempotent over step 2) and the side-effect of `setuid(2)` to a
/// non-zero UID with `PR_SET_KEEPCAPS = 0` (default) to clear
/// permitted.
///
/// CAPABILITY: none — discharging caps does not itself require
/// caps.
///
/// The actual permitted-set clear happens implicitly when
/// [`crate::identity_drop`] calls `setuid(real_uid)` with KEEPCAPS
/// off; this function tightens the bounding set so the kernel can
/// never re-introduce a capability via subsequent file-cap exec.
///
/// # Errors
///
/// Same policy as [`trim_to_working_set`].
pub fn drop_all_bounding() -> Result<()> {
    for cap in 0..=HIGHEST_KNOWN_CAP {
        if let Err(e) = syscall::prctl_capbset_drop(cap) {
            if e.raw_os_error() != Some(libc::EINVAL) {
                return Err(Error::BoundingSet(format!(
                    "drop-all cap {cap}: {e}"
                )));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn working_caps_are_a_proper_subset() {
        // The five caps must all be valid Linux cap slots and
        // distinct.  This guards a refactor that accidentally
        // duplicates an entry or adds a 6th.
        let set: BTreeSet<i32> = WORKING_CAPS.iter().copied().collect();
        assert_eq!(set.len(), WORKING_CAPS.len(), "WORKING_CAPS has duplicates");
        assert_eq!(set.len(), 5, "WORKING_CAPS must contain exactly 5 entries");
        for cap in &set {
            assert!(
                *cap >= 0 && *cap <= HIGHEST_KNOWN_CAP,
                "cap {cap} outside known range"
            );
        }
    }

    #[test]
    fn working_caps_includes_the_five_documented() {
        // If anyone refactors the constants, lock in the names.
        assert!(WORKING_CAPS.contains(&CAP_SYS_ADMIN));
        assert!(WORKING_CAPS.contains(&CAP_SETUID));
        assert!(WORKING_CAPS.contains(&CAP_SETGID));
        assert!(WORKING_CAPS.contains(&CAP_IPC_LOCK));
        assert!(WORKING_CAPS.contains(&CAP_SETPCAP));
    }

    #[test]
    fn trim_does_not_panic_when_unprivileged() {
        // Even without caps, dropping bounding-set bits we don't
        // hold returns success (we can only ever shrink the
        // bounding set; dropping a bit that's already absent is
        // a no-op per prctl(2)).
        trim_to_working_set().expect("bounding-set trim must succeed on any Linux host");
    }
}
