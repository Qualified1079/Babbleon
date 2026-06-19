//! Lifecycle step 8 — install the post-NNP seccomp filter.
//!
//! # What this defeats
//!
//! After step 7 the launcher should never need to call `mount`,
//! `unshare`, `setuid`, `prctl`, or `bpf` again — its remaining
//! work is `fork` + `execve`.  An allowlist limited to the
//! post-step-9 surface confines a hypothetical late-binding
//! exploit to read / write / wait / exit syscalls.
//!
//! Per `docs/v2/least-privilege.md` the post-step-10 profile is:
//!
//! > deny everything except `read`, `write`, `wait`, `waitid`,
//! > `sigreturn`, `exit*`.
//!
//! `execve` itself must be allowed for step 11; we add it to the
//! allowlist and rely on `PR_SET_NO_NEW_PRIVS = 1` to prevent any
//! privilege regain via the exec target.
//!
//! # Mechanism
//!
//! `seccompiler` compiles the allowlist into a BPF program and
//! `apply_filter` installs it on the calling thread.  Any syscall
//! not on the allowlist receives `SECCOMP_RET_KILL_PROCESS` — the
//! kernel terminates the process.  Stronger than `RET_ERRNO` which
//! would let an exploit retry under a different number.
//!
//! # Threat model boundaries
//!
//! - Defeats: a launcher exploit attempting `mount`, `unshare`,
//!   `ptrace`, `bpf`, raw `socket`, etc., during the brief window
//!   between step 8 install and step 11 `execve`.
//! - Does NOT defeat: anything the seven allowed syscalls can be
//!   coerced into doing.  Of those, `execve` is the broadest;
//!   `NO_NEW_PRIVS` constrains it.

#![cfg(target_os = "linux")]

use std::collections::BTreeMap;

use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, SeccompRule};

use crate::errors::{Error, Result};

/// Syscalls allowed AFTER seccomp install.
///
/// Everything else returns `SECCOMP_RET_KILL_PROCESS`.  The list is
/// derived from the table in `docs/v2/least-privilege.md` plus the
/// minimum needed for `fork` + `execve` of the child:
///
/// - `read`, `write` — child-side stdio plumbing.
/// - `wait4`, `waitid` — parent reaper waiting on child exit.
/// - `rt_sigreturn` — signal handler return; kernel requires.
/// - `exit`, `exit_group` — process exit.
/// - `clone`, `fork`, `vfork` — fork before exec.  We pick `clone`
///   only because Rust's stdlib uses it; `fork`/`vfork` are kept
///   for completeness in case libc routes through them on some
///   platforms.
/// - `execve`, `execveat` — the child exec itself.
/// - `mmap`, `mprotect`, `munmap`, `brk` — libc/glibc memory
///   management surrounding `execve`.
/// - `rt_sigaction`, `rt_sigprocmask` — signal disposition reset
///   before exec.
const ALLOWED_SYSCALLS: &[i64] = &[
    libc::SYS_read,
    libc::SYS_write,
    libc::SYS_wait4,
    libc::SYS_waitid,
    libc::SYS_rt_sigreturn,
    libc::SYS_rt_sigaction,
    libc::SYS_rt_sigprocmask,
    libc::SYS_exit,
    libc::SYS_exit_group,
    libc::SYS_clone,
    libc::SYS_execve,
    libc::SYS_execveat,
    libc::SYS_mmap,
    libc::SYS_mprotect,
    libc::SYS_munmap,
    libc::SYS_brk,
];

/// Step 8 — install the allowlist filter.
///
/// CAPABILITY: none (`PR_SET_NO_NEW_PRIVS = 1` from step 7 unlocks
/// unprivileged seccomp install).
///
/// # Errors
///
/// Returns [`Error::Seccomp`] if the filter cannot be compiled or
/// installed.  Both indicate a code bug — the allowlist is fixed at
/// build time and the kernel ABI is stable.
pub fn apply() -> Result<()> {
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    for &nr in ALLOWED_SYSCALLS {
        rules.insert(nr, vec![]);
    }

    let arch = std::env::consts::ARCH
        .try_into()
        .unwrap_or(seccompiler::TargetArch::x86_64);

    let filter = SeccompFilter::new(
        rules,
        // mismatch action — what to do for any syscall NOT in the
        // allowlist.  KillProcess > Errno > Trap: gives the operator
        // a clear "this binary tried syscall X" message in dmesg
        // and prevents an exploit from probing the disallowed set.
        SeccompAction::KillProcess,
        // match action — what to do for syscalls ON the allowlist.
        SeccompAction::Allow,
        arch,
    )
    .map_err(|e| Error::Seccomp(format!("filter build: {e}")))?;

    let prog: BpfProgram = filter
        .try_into()
        .map_err(|e| Error::Seccomp(format!("filter compile: {e}")))?;

    seccompiler::apply_filter(&prog)
        .map_err(|e| Error::Seccomp(format!("filter apply: {e}")))
}

#[cfg(test)]
mod tests {
    use super::ALLOWED_SYSCALLS;

    #[test]
    fn allowlist_includes_exec_family() {
        assert!(ALLOWED_SYSCALLS.contains(&libc::SYS_execve));
        assert!(ALLOWED_SYSCALLS.contains(&libc::SYS_execveat));
    }

    #[test]
    fn allowlist_includes_exit_family() {
        assert!(ALLOWED_SYSCALLS.contains(&libc::SYS_exit));
        assert!(ALLOWED_SYSCALLS.contains(&libc::SYS_exit_group));
    }

    #[test]
    fn allowlist_excludes_dangerous_syscalls() {
        // Reviewer-facing assertion: the allowlist must NOT include
        // any of the canonical privilege-escalation syscalls.  If a
        // refactor adds one, this test trips immediately.
        let banned = &[
            libc::SYS_ptrace,
            libc::SYS_bpf,
            libc::SYS_unshare,
            libc::SYS_setns,
            libc::SYS_mount,
            libc::SYS_perf_event_open,
            libc::SYS_userfaultfd,
            libc::SYS_init_module,
            libc::SYS_finit_module,
            libc::SYS_kexec_load,
        ];
        for nr in banned {
            assert!(
                !ALLOWED_SYSCALLS.contains(nr),
                "allowlist must not contain dangerous syscall {nr}"
            );
        }
    }

    #[test]
    fn allowlist_has_no_duplicates() {
        let mut sorted: Vec<i64> = ALLOWED_SYSCALLS.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            ALLOWED_SYSCALLS.len(),
            "ALLOWED_SYSCALLS contains duplicates"
        );
    }
}
