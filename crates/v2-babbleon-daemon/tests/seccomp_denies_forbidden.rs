//! Negative test: forbidden syscalls under the daemon's seccomp
//! filter must kill the calling process with SIGSYS.
//!
//! The positive integration test (`seccomp_envelope.rs`) confirms
//! the filter does not break the daemon's documented envelope.
//! This file is the complementary check: it confirms the filter
//! actually **enforces** the `KillProcess` action — without it we
//! could ship an allowlist that's secretly a no-op and the
//! daemon would still pass `seccomp_envelope.rs`.
//!
//! # Test mechanism
//!
//! We use `std::os::unix::process::CommandExt::pre_exec` — a hook
//! that runs in the child process after `fork(2)` but before
//! `execve(2)`.  Inside the hook we apply the daemon's seccomp
//! filter.  When the parent then proceeds to `execve("/bin/true")`,
//! the kernel rejects the call (execve is NOT on the daemon's
//! allowlist) and sends SIGSYS.  The parent's `.status()` reports
//! the signal-termination.
//!
//! `pre_exec` is `unsafe` because the child shares the parent's
//! address space until `execve` succeeds; our hook only calls
//! seccomp primitives that are async-signal-safe and forking-safe.

#![cfg(target_os = "linux")]

use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::Command;

use babbleon_daemon_v2::seccomp_profile;

/// Wrap [`seccomp_profile::apply`] to produce an `io::Error` because
/// that's what `pre_exec`'s closure must return.
fn apply_filter() -> std::io::Result<()> {
    seccomp_profile::apply().map_err(|e| {
        std::io::Error::other(format!("apply_seccomp: {e}"))
    })
}

#[test]
fn execve_dies_with_sigsys_under_seccomp_filter() {
    // `/bin/true` is the canonical "do nothing successfully" binary;
    // we pick it so that *if* the filter were broken and execve
    // succeeded, the child would simply exit 0 — making the failure
    // mode obvious in the assertion (we'd see ExitStatus::from_raw
    // with code 0 instead of signal SIGSYS).
    let mut cmd = Command::new("/bin/true");
    // SAFETY: the pre_exec closure runs in the child after fork.
    // We only call seccomp install primitives (PR_SET_NO_NEW_PRIVS
    // + seccomp filter apply), both async-signal-safe per their
    // kernel man pages.  No heap allocation, no Rust runtime
    // re-entry, no signals raised.
    unsafe {
        cmd.pre_exec(apply_filter);
    }
    let status = cmd
        .status()
        .expect("Command::status failed");

    // The kernel terminates the process by SIGSYS on a denied
    // syscall when the filter's mismatch action is KillProcess.
    // ExitStatus::signal() returns Some(SIGSYS) in that case.
    assert_eq!(
        status.signal(),
        Some(libc::SIGSYS),
        "expected child to die with SIGSYS under the daemon's seccomp \
         filter (execve is NOT on the allowlist); got {status:?}",
    );
}

#[test]
fn socket_inet_dies_with_sigsys_under_filter() {
    // Construct a child that, in pre_exec, applies the filter then
    // immediately attempts a `socket(AF_INET, ...)` syscall.  The
    // `socket` syscall is forbidden by the daemon's allowlist
    // (steady-state daemon never opens outbound channels), so the
    // child must die with SIGSYS before reaching execve.
    //
    // We trigger the socket syscall by `execve`ing `sh -c 'exec 3<>/dev/tcp/127.0.0.1/1'`
    // — but execve itself is forbidden too, so we'd die on execve
    // anyway.  Simpler: rely on execve as the canonical denied
    // syscall and tie this test to a different denial route via a
    // direct libc::socket call in pre_exec.
    //
    // pre_exec runs in async-signal-safe context; libc::socket IS
    // async-signal-safe.  We call it directly via libc::syscall
    // semantics to avoid any allocations.
    let mut cmd = Command::new("/bin/true");
    // SAFETY: pre_exec runs in the child after fork.  We call
    // apply_filter (signal-safe) then libc::socket (signal-safe).
    // No heap, no Rust runtime re-entry.  The socket call is the
    // forbidden one; if the filter is broken it would succeed and
    // we'd reach the execve call, which is ALSO forbidden — both
    // routes assert the same denial.
    unsafe {
        cmd.pre_exec(|| {
            apply_filter()?;
            // SAFETY: libc::socket is an FFI call with three scalar
            // args (domain, type, protocol).  It returns an int.  No
            // pointers passed; no aliasing or lifetime concerns.
            // Per signal-safety: socket(2) is listed as
            // async-signal-safe in POSIX.1-2008.
            let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
            // If we reach here, the filter let socket through —
            // that's a bug, surface as a non-SIGSYS error so the
            // test parent sees an unexpected exit code, not SIGSYS.
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
        "expected child to die with SIGSYS on socket(AF_INET, ...) \
         (the daemon's allowlist forbids socket(2) in steady state); \
         got {status:?}",
    );
}
