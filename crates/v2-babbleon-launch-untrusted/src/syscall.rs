//! Isolated `unsafe` libc wrappers for the launcher's privileged
//! syscall surface.
//!
//! # Why this module exists
//!
//! Per `docs/v2/security-baseline.md` rule 1 exception policy, the
//! launcher crate replaces `forbid(unsafe_code)` with `deny` and
//! quarantines every `unsafe` block to this single file.  All other
//! launcher modules import from here and never call `libc::*`
//! directly.
//!
//! Auditors verify the launcher's complete unsafe surface by reading
//! exactly one file — this one.  Adding an unsafe block outside this
//! module is a merge blocker.
//!
//! # Syscalls wrapped
//!
//! - `prctl(PR_CAPBSET_DROP, cap, 0, 0, 0)` — drop one capability
//!   from the bounding set.
//! - `prctl(PR_SET_DUMPABLE, 0, ...)` — refuse core dumps.
//! - `prctl(PR_SET_NO_NEW_PRIVS, 1, ...)` — forbid future privilege
//!   elevation across `execve`.
//! - `prctl(PR_SET_KEEPCAPS, 0, ...)` — discard caps across setuid
//!   (paired with the explicit drop in step 10).
//!
//! Higher-level wrappers (`mount`, `unshare`, `setuid`, `setgid`,
//! `mlockall`, `setrlimit`) live in `nix` which already audits its
//! own unsafe; the launcher modules call those `nix` wrappers
//! directly without going through this file.

#![cfg(target_os = "linux")]
#![allow(unsafe_code)]
#![deny(clippy::undocumented_unsafe_blocks)]

use std::io;

/// Drop one capability from the calling process's bounding set.
///
/// Returns the raw libc result; the caller is responsible for
/// interpreting `EINVAL` (capability slot not allocated on this
/// kernel — harmless) versus any other errno (genuine failure).
///
/// # CAPABILITY
///
/// None.  `PR_CAPBSET_DROP` on the calling process is unprivileged.
/// The drop only ever shrinks the bounding set, never enlarges it.
///
/// # Errors
///
/// Returns `io::Error::last_os_error()` if `prctl` returns non-zero.
pub fn prctl_capbset_drop(cap: i32) -> io::Result<()> {
    // SAFETY: `prctl(2)` is a kernel ABI that accepts five scalar
    // arguments.  `PR_CAPBSET_DROP` reads only the first additional
    // arg (the capability number).  We pass it as an unsigned long
    // and zero for the unused trailing args.  No pointers, no
    // aliasing, no lifetime — the call is value-only.  The kernel
    // is responsible for validating `cap` against `CAP_LAST_CAP`
    // and returning `EINVAL` if it's out of range.
    let ret = unsafe {
        libc::prctl(
            libc::PR_CAPBSET_DROP,
            libc::c_ulong::try_from(cap).unwrap_or(0),
            0,
            0,
            0,
        )
    };
    if ret == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Disable core-dump generation for the calling process.
///
/// # CAPABILITY
///
/// None.  `PR_SET_DUMPABLE` to 0 (SUID_DUMP_DISABLE) is always
/// allowed for the calling process.
///
/// # Errors
///
/// Returns `io::Error::last_os_error()` if `prctl` returns non-zero
/// (in practice this only happens if the kernel was compiled
/// without CONFIG_COREDUMP, which is extremely rare).
pub fn prctl_set_dumpable_off() -> io::Result<()> {
    // SAFETY: `PR_SET_DUMPABLE` with arg `SUID_DUMP_DISABLE` (== 0)
    // is documented as taking no further arguments; we pass zeros.
    // Pure scalar args; no aliasing.
    let ret = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
    if ret == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Set `PR_SET_NO_NEW_PRIVS = 1` so no future `execve` can grant
/// privileges via file caps or setuid bits.
///
/// # CAPABILITY
///
/// None.  Unprivileged operation by design.
///
/// # Errors
///
/// `io::Error::last_os_error()` on non-zero return.
pub fn prctl_set_no_new_privs() -> io::Result<()> {
    // SAFETY: `PR_SET_NO_NEW_PRIVS` takes `1` and three zero
    // padding args per Documentation/prctl/no_new_privs.txt.  Pure
    // scalar; no pointer aliasing.
    let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if ret == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Ensure capabilities are NOT preserved across `setuid` so the
/// final `setuid(real_uid)` clears the effective capability set as
/// a side-effect of changing UID.
///
/// # CAPABILITY
///
/// None.  Per `prctl(2)`, `PR_SET_KEEPCAPS` is unprivileged for the
/// caller.
///
/// # Errors
///
/// `io::Error::last_os_error()` on non-zero return.
pub fn prctl_set_keepcaps_off() -> io::Result<()> {
    // SAFETY: `PR_SET_KEEPCAPS` with arg 0 means "do not preserve
    // capabilities across setuid".  Scalar-only ABI.
    let ret = unsafe { libc::prctl(libc::PR_SET_KEEPCAPS, 0, 0, 0, 0) };
    if ret == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Read the effective capability set of the calling process via
/// `capget(2)` and return it as a 64-bit bitmask (concatenated
/// upper/lower 32-bit words, upper << 32).
///
/// Used by the post-step-10 self-check that asserts the permitted
/// set is empty before exec.
///
/// # CAPABILITY
///
/// None.  Reading own capabilities is unprivileged.
///
/// # Errors
///
/// `io::Error::last_os_error()` if `capget` fails.  Note that some
/// minimal kernel configs without `CONFIG_MULTIUSER` may not expose
/// `capget`; in that case the launcher's self-check degrades to a
/// log warning.
pub fn capget_effective_bitmask() -> io::Result<u64> {
    #[repr(C)]
    #[derive(Default, Copy, Clone)]
    struct CapUserHeader {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    #[derive(Default, Copy, Clone)]
    struct CapUserData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }

    // _LINUX_CAPABILITY_VERSION_3 — the only version we ever read.
    const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

    let header = CapUserHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0, // 0 = self
    };
    let mut data = [CapUserData::default(); 2];

    // SAFETY: `syscall(SYS_capget, hdrp, datap)` is the documented
    // kernel ABI: `hdrp` points to one `__user_cap_header_struct`,
    // `datap` to TWO `__user_cap_data_struct` entries (because we
    // declared VERSION_3).  Both pointers are to stack-resident
    // structs of the correct layout and size.  We pass the actual
    // address of each; the kernel writes into `data` and does not
    // retain the pointers past the syscall.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_capget,
            std::ptr::addr_of!(header),
            std::ptr::addr_of_mut!(data),
        )
    };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    let lower = u64::from(data[0].effective);
    let upper = u64::from(data[1].effective);
    Ok((upper << 32) | lower)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prctl_set_dumpable_off_succeeds() {
        // Self-targeted; always allowed.  If this fails the test
        // host is broken in an interesting way.
        prctl_set_dumpable_off().expect("PR_SET_DUMPABLE=0 should not fail on a sane Linux host");
    }

    #[test]
    fn prctl_set_keepcaps_off_succeeds() {
        prctl_set_keepcaps_off().expect("PR_SET_KEEPCAPS=0 should not fail");
    }

    #[test]
    fn capget_returns_some_bitmask() {
        // We don't assert the value (CI runners hold different sets
        // depending on container config); we assert the syscall
        // succeeds.  An unprivileged process always succeeds at
        // capget on itself.
        let _ = capget_effective_bitmask().expect("capget(self) must succeed");
    }
}
