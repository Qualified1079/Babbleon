//! Negative test: forbidden syscalls under the launcher's step-8
//! seccomp filter must kill the calling process with SIGSYS.
//!
//! The launcher's allowlist (in
//! `src/seccomp_profile.rs::ALLOWED_SYSCALLS`) is unit-tested for
//! structure — what's in, what's out.  That catches drift.  This
//! file is the complementary check: the filter ACTUALLY ENFORCES
//! the `KillProcess` mismatch action.  Without these tests, a
//! regression that produced a no-op BPF program would still pass
//! the structure tests.
//!
//! # Test mechanism
//!
//! Same pattern as the daemon's `seccomp_denies_forbidden.rs`: we
//! use `std::os::unix::process::CommandExt::pre_exec` — a hook
//! that runs in the child after `fork(2)` but before `execve(2)`.
//! In the hook we:
//!
//! 1. Set `PR_SET_NO_NEW_PRIVS = 1` (required for unprivileged
//!    seccomp install).
//! 2. Install the launcher's step-8 filter.
//! 3. Issue a forbidden syscall via `libc::*`.
//!
//! If the filter is correct, the kernel raises SIGSYS at step 3
//! before `execve` is reached.  The parent's `.status()` reports
//! `ExitStatus::signal() == Some(SIGSYS)`.
//!
//! # Choice of forbidden syscall
//!
//! The launcher's allowlist deliberately permits `execve` — step
//! 11 of the lifecycle execs the child command.  So we cannot use
//! execve as the canary (it's allowed).  We pick `openat(2)`
//! instead: forbidden by the launcher's profile because by the
//! time the filter installs, all the launcher's file work is
//! already done (the activated table was read pre-step-2, the
//! tmpfs+bind mounts pre-step-8).  Any `openat` call from
//! post-step-10 code is therefore suspect.
//!
//! # Why a separate test file from the unit tests
//!
//! The unit tests run in-process; calling `apply()` in a unit test
//! would seccomp-confine the test runner itself and prevent
//! subsequent tests from running.  Integration tests get their own
//! process per `#[test]`, so each one is free to apply the filter
//! and die.

#![cfg(target_os = "linux")]

use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::Command;

use v2_babbleon_launch_untrusted::{process_hardening, seccomp_profile};

/// Wrap step-7 NNP + step-8 seccomp install into one fallible
/// helper that fits `Command::pre_exec`'s `FnMut() -> io::Result<()>`.
fn apply_step7_then_step8() -> std::io::Result<()> {
    process_hardening::set_no_new_privs().map_err(|e| {
        std::io::Error::other(format!("step 7 NNP: {e}"))
    })?;
    seccomp_profile::apply().map_err(|e| {
        std::io::Error::other(format!("step 8 seccomp: {e}"))
    })?;
    Ok(())
}

#[test]
fn openat_dies_with_sigsys_under_launcher_filter() {
    let mut cmd = Command::new("/bin/true");
    // SAFETY: pre_exec runs in the child after fork.  We call only
    // async-signal-safe primitives (prctl, seccomp filter apply,
    // openat).  No heap allocation; no Rust runtime re-entry.
    unsafe {
        cmd.pre_exec(|| {
            apply_step7_then_step8()?;
            // SAFETY: libc::openat is an FFI call with three scalar
            // args + one NUL-terminated string pointer (a static
            // string literal — lifetime is 'static).  The kernel
            // copies the path before returning; no aliasing.
            let fd = libc::openat(
                libc::AT_FDCWD,
                c"/dev/null".as_ptr(),
                libc::O_RDONLY,
            );
            // If we reach here, the filter let openat through —
            // that's a bug.  Close the fd to keep the child clean
            // and let the parent see an unexpected exit.
            if fd >= 0 {
                libc::close(fd);
            }
            Ok(())
        });
    }
    let status = cmd.status().expect("Command::status failed");
    assert_eq!(
        status.signal(),
        Some(libc::SIGSYS),
        "expected child to die with SIGSYS on openat(2) (the \
         launcher's seccomp allowlist forbids openat in steady \
         state); got {status:?}",
    );
}

#[test]
fn socket_dies_with_sigsys_under_launcher_filter() {
    let mut cmd = Command::new("/bin/true");
    // SAFETY: see openat case above — same reasoning.
    unsafe {
        cmd.pre_exec(|| {
            apply_step7_then_step8()?;
            // SAFETY: libc::socket is a scalar-only FFI call;
            // async-signal-safe per POSIX.1-2008.
            let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
            if fd >= 0 {
                libc::close(fd);
            }
            Ok(())
        });
    }
    let status = cmd.status().expect("Command::status failed");
    assert_eq!(
        status.signal(),
        Some(libc::SIGSYS),
        "expected child to die with SIGSYS on socket(AF_INET, ...): \
         the launcher's seccomp allowlist forbids the socket family. \
         Got {status:?}",
    );
}

#[test]
fn ptrace_dies_with_sigsys_under_launcher_filter() {
    // Ptrace is the canonical denial target: launcher's job is to
    // protect the user's untrusted-tier process from same-uid
    // introspection.  Letting ptrace through here would silently
    // negate that.
    let mut cmd = Command::new("/bin/true");
    // SAFETY: pre_exec sequencing as above.  ptrace is
    // async-signal-safe.
    unsafe {
        cmd.pre_exec(|| {
            apply_step7_then_step8()?;
            // SAFETY: libc::ptrace is varargs-ABI but the
            // PTRACE_TRACEME call takes no further arguments.
            // We pass zeros to keep the call well-formed.
            let r = libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0);
            if r >= 0 {
                // shouldn't happen — filter would have killed us
            }
            Ok(())
        });
    }
    let status = cmd.status().expect("Command::status failed");
    assert_eq!(
        status.signal(),
        Some(libc::SIGSYS),
        "expected child to die with SIGSYS on ptrace(PTRACE_TRACEME) \
         (the launcher's seccomp allowlist forbids ptrace); got {status:?}",
    );
}
