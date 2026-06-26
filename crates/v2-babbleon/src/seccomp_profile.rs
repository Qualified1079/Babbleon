//! Preprocessor seccomp filter — allowlist of every syscall the
//! `babbleon scramble` / `babbleon unscramble` path makes after the
//! daemon socket is connected.
//!
//! # What this defeats
//!
//! The scramble/unscramble path processes untrusted source files.  A
//! code-flow bug in the tokenizer, L2 identifier scrambler, or L3
//! whitespace encoder could grant an attacker arbitrary syscall
//! execution.  The seccomp filter documented here bounds the
//! post-connection syscall surface to the **34 syscalls** listed in
//! `docs/v2/preprocessor-seccomp-envelope.md`.  Everything else
//! returns `SECCOMP_RET_KILL_PROCESS` — the kernel terminates the
//! process before a forbidden call can be issued (e.g. `execve` of a
//! shell, `socket` to exfiltrate data, `ptrace` of a peer process).
//!
//! # Install point
//!
//! The filter installs inside `run_scramble` / `run_unscramble` (and
//! the corpus-dir variants) AFTER the daemon socket round-trip
//! completes and BEFORE the CPU-bound L2/L3/L4/L5 computation begins.
//! This means:
//!
//! - `socket` + `connect` (for the daemon IPC) run before the filter
//!   and are NOT on the allowlist.
//! - The filter does not restrict `init`, `unlock`, `status`, or
//!   `rotate-mapping` subcommands (they do not call `apply()`).
//!
//! # Default: ON
//!
//! Seccomp installs by default on every `scramble`/`unscramble` run.
//! Pass `--no-seccomp` to skip it for debugging; the CLI prints a
//! warning when seccomp is skipped, deliberately not suppressible so
//! operators can detect a broken deploy.
//!
//! # Threat model boundaries
//!
//! - **Defeats:** an exploit that gains arbitrary syscall execution
//!   inside the scramble computation (tokenizer, HKDF compound
//!   lookup, L3 encoder).
//! - **Does NOT defeat:** an exploit that runs before the filter
//!   installs (the daemon socket connect, header parse, and source
//!   file read all happen pre-filter; v2.1 can tighten the install
//!   point to before the source-file open).
//! - **Does NOT defeat:** anything the 33 allowed syscalls can be
//!   coerced into doing.  `openat` + `write` remain; an attacker
//!   would need to divert a file FD.  The CLI runs as the operator's
//!   UID so the blast radius is bounded to UID-writable files.
//! - **Does NOT defeat:** kernel CVEs in the allowed syscalls.

#![cfg(target_os = "linux")]

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use nix::sys::prctl::set_no_new_privs;
use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, SeccompRule};

/// Syscalls the preprocessor allows after the seccomp filter installs.
///
/// Derived from `docs/v2/preprocessor-seccomp-envelope.md`.
/// The install point is AFTER the daemon socket round-trip (so
/// `socket`, `connect`, `read`/`write` on the socket FD are done).
const ALLOWED_SYSCALLS: &[i64] = &[
    // ---- File I/O ----
    libc::SYS_read,
    libc::SYS_write,
    libc::SYS_close,
    libc::SYS_openat,
    // writev — BufWriter flush and some tracing sinks emit writev(2).
    libc::SYS_writev,
    // lseek — std::io::Seek on file descriptors (header vs. body reads).
    libc::SYS_lseek,
    // ioctl — tracing-subscriber checks isatty(TCGETS) on stdout for
    // ANSI colour detection.
    libc::SYS_ioctl,
    // ---- File metadata ----
    libc::SYS_fstat,
    libc::SYS_newfstatat,
    libc::SYS_statx,
    // fcntl — Rust std F_GETFL / F_SETFL and F_DUPFD_CLOEXEC on
    // tempfile creation.
    libc::SYS_fcntl,
    // ---- Directory ops (scramble-dir / unscramble-dir) ----
    // getdents64 — std::fs::read_dir (walks source tree).
    libc::SYS_getdents64,
    // mkdir — std::fs::create_dir_all on the output tree.
    libc::SYS_mkdir,
    // unlinkat — scramble-dir --force removes stale output files.
    libc::SYS_unlinkat,
    // rmdir — scramble-dir --force prunes empty output dirs.
    libc::SYS_rmdir,
    // ---- Memory ----
    libc::SYS_brk,
    libc::SYS_mmap,
    libc::SYS_mprotect,
    libc::SYS_munmap,
    libc::SYS_madvise,
    libc::SYS_mremap,
    // ---- Signals + thread sync ----
    libc::SYS_rt_sigaction,
    libc::SYS_rt_sigprocmask,
    libc::SYS_rt_sigreturn,
    libc::SYS_restart_syscall,
    libc::SYS_sigaltstack,
    libc::SYS_futex,
    // ---- Time + read-only identity ----
    libc::SYS_clock_gettime,
    libc::SYS_getpid,
    libc::SYS_gettid,
    // ---- Randomness (HashMap re-seed on identifier mapping build) ----
    libc::SYS_getrandom,
    // ---- Exit ----
    libc::SYS_exit,
    libc::SYS_exit_group,
    // rseq — Rust runtime TLS/thread teardown on some kernels.
    libc::SYS_rseq,
];

/// Apply `PR_SET_NO_NEW_PRIVS = 1` then install the preprocessor's
/// seccomp allowlist on the current thread.
///
/// Call this AFTER the daemon socket round-trip completes and BEFORE
/// the L2/L3/L4/L5 computation begins.
///
/// # Errors
///
/// Returns an error if either `prctl` or the seccomp install fails.
/// The CLI propagates this as fatal — seccomp is on by default and
/// silently running unfiltered defeats the secure default.
pub fn apply() -> Result<()> {
    set_no_new_privs()
        .context("PR_SET_NO_NEW_PRIVS=1 (prctl) failed")?;

    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    for &nr in ALLOWED_SYSCALLS {
        rules.insert(nr, vec![]);
    }

    let arch = std::env::consts::ARCH
        .try_into()
        .unwrap_or(seccompiler::TargetArch::x86_64);

    let filter = SeccompFilter::new(
        rules,
        SeccompAction::KillProcess,
        SeccompAction::Allow,
        arch,
    )
    .context("seccomp filter build failed")?;

    let prog: BpfProgram = filter
        .try_into()
        .context("seccomp filter compile failed")?;

    seccompiler::apply_filter(&prog)
        .context("seccomp filter apply failed")?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::ALLOWED_SYSCALLS;

    #[test]
    fn allowlist_includes_core_file_io() {
        assert!(ALLOWED_SYSCALLS.contains(&libc::SYS_read));
        assert!(ALLOWED_SYSCALLS.contains(&libc::SYS_write));
        assert!(ALLOWED_SYSCALLS.contains(&libc::SYS_close));
        assert!(ALLOWED_SYSCALLS.contains(&libc::SYS_openat));
    }

    #[test]
    fn allowlist_includes_exit_family() {
        assert!(ALLOWED_SYSCALLS.contains(&libc::SYS_exit));
        assert!(ALLOWED_SYSCALLS.contains(&libc::SYS_exit_group));
    }

    #[test]
    fn allowlist_excludes_socket_family() {
        // Daemon connection completes BEFORE the filter installs.
        // Allowing socket/connect in the computation window would let
        // a tokenizer exploit open an outbound channel.
        assert!(!ALLOWED_SYSCALLS.contains(&libc::SYS_socket));
        assert!(!ALLOWED_SYSCALLS.contains(&libc::SYS_connect));
        assert!(!ALLOWED_SYSCALLS.contains(&libc::SYS_bind));
        assert!(!ALLOWED_SYSCALLS.contains(&libc::SYS_listen));
        assert!(!ALLOWED_SYSCALLS.contains(&libc::SYS_accept4));
    }

    #[test]
    fn allowlist_excludes_execve_family() {
        assert!(!ALLOWED_SYSCALLS.contains(&libc::SYS_execve));
        assert!(!ALLOWED_SYSCALLS.contains(&libc::SYS_execveat));
    }

    #[test]
    fn allowlist_excludes_fork_family() {
        assert!(!ALLOWED_SYSCALLS.contains(&libc::SYS_fork));
        assert!(!ALLOWED_SYSCALLS.contains(&libc::SYS_vfork));
        assert!(!ALLOWED_SYSCALLS.contains(&libc::SYS_clone));
        assert!(!ALLOWED_SYSCALLS.contains(&libc::SYS_clone3));
    }

    #[test]
    fn allowlist_excludes_privilege_escalation_surface() {
        let banned = &[
            libc::SYS_ptrace,
            libc::SYS_process_vm_readv,
            libc::SYS_process_vm_writev,
            libc::SYS_bpf,
            libc::SYS_unshare,
            libc::SYS_setns,
            libc::SYS_mount,
            libc::SYS_umount2,
            libc::SYS_perf_event_open,
            libc::SYS_userfaultfd,
            libc::SYS_init_module,
            libc::SYS_finit_module,
            libc::SYS_kexec_load,
            libc::SYS_setuid,
            libc::SYS_setgid,
            libc::SYS_setgroups,
            libc::SYS_keyctl,
            libc::SYS_add_key,
            libc::SYS_request_key,
            libc::SYS_pidfd_open,
            libc::SYS_pidfd_getfd,
            libc::SYS_pidfd_send_signal,
            libc::SYS_kcmp,
            libc::SYS_prctl,
        ];
        for nr in banned {
            assert!(
                !ALLOWED_SYSCALLS.contains(nr),
                "allowlist must not contain dangerous syscall {nr}",
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
            "ALLOWED_SYSCALLS contains duplicates",
        );
    }

    #[test]
    fn allowlist_size_matches_envelope_doc() {
        // docs/v2/preprocessor-seccomp-envelope.md enumerates 34
        // syscalls for the scramble/unscramble steady-state window.
        // If this count drifts, update the envelope doc and this test
        // in the same commit.
        assert_eq!(
            ALLOWED_SYSCALLS.len(),
            34,
            "allowlist drifted from docs/v2/preprocessor-seccomp-envelope.md \
             (34 documented; this code lists {}).  Update both.",
            ALLOWED_SYSCALLS.len(),
        );
    }
}
