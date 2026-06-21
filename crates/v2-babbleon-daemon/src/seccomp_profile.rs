//! Daemon seccomp filter — allowlist of every syscall the daemon
//! makes in steady state.
//!
//! # What this defeats
//!
//! The daemon holds the per-host secret in `Zeroizing<[u8; 32]>`.  An
//! exploit reaching arbitrary syscall execution (via a code-flow
//! bug in the request parser, the wrapper renderer, or the HKDF
//! path) would otherwise have the full kernel ABI available.  The
//! seccomp filter installed by this module bounds the post-bind
//! syscall surface to the **32 syscalls** documented in
//! `docs/v2/daemon-seccomp-envelope.md`.  Everything else returns
//! `SECCOMP_RET_KILL_PROCESS` — the kernel terminates the daemon
//! before the exploit can issue a forbidden call (e.g. `execve` of a
//! shell, `socket` to exfiltrate the secret, `ptrace` of a sibling
//! process).
//!
//! # Mechanism
//!
//! Identical pattern to the launcher's step-8 seccomp:
//!
//! 1. Build a `BTreeMap<syscall_nr, Vec<SeccompRule>>` with the
//!    allowlist (no argument filtering — name-only).
//! 2. Compile into a BPF program via `seccompiler`.
//! 3. Install on the current thread via `seccompiler::apply_filter`.
//!
//! The filter installs only after `PR_SET_NO_NEW_PRIVS = 1` is set.
//! The daemon's `main` runs this sequence between `bind_socket`
//! (which needs `socket`+`bind`, not on the allowlist) and the
//! first `accept` in the serve loop.
//!
//! # Default: ON
//!
//! Seccomp is installed BY DEFAULT at daemon startup.  The
//! envelope is documented in `docs/v2/daemon-seccomp-envelope.md`
//! (40 syscalls).  Operators who need to iterate on code paths
//! that may add a new syscall pass `--no-seccomp` to skip the
//! install for that run; production deployments leave the
//! default in place.  The legacy `--enable-seccomp` flag is
//! kept as a hidden no-op alias for back-compat with phase-2
//! scripts; it emits a deprecation warning and will be removed
//! in v2.1.  CI drift detection lives in
//! `tests/seccomp_envelope.rs`.
//!
//! # Threat model boundaries
//!
//! - **Defeats:** an exploit that gains arbitrary syscall execution
//!   after the filter is installed.  The kernel rejects forbidden
//!   syscalls without giving the exploit a chance to retry.
//! - **Does NOT defeat:** an exploit that runs during startup,
//!   before the filter installs (the socket bind, the wordlist
//!   load, the per-host-secret construction all happen pre-filter).
//!   That window is bounded and the work it does is well-trodden
//!   (no peer input has been read yet).
//! - **Does NOT defeat:** anything the 32 allowed syscalls can be
//!   coerced into doing.  The broadest is `openat` (combined with
//!   `write`); a bug that turns these into an arbitrary-write
//!   primitive remains in scope.  Compensating control: the
//!   `wrapper_dir` is the only path the daemon writes to, and the
//!   daemon's UID owns it — a same-UID attacker is the only one
//!   who can move that write to a different victim.
//! - **Does NOT defeat:** kernel CVEs in the allowed syscalls.
//!   Defense in depth via the host's kernel-update cadence.

#![cfg(target_os = "linux")]

use std::collections::BTreeMap;

use nix::sys::prctl::set_no_new_privs;
use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, SeccompRule};

use crate::errors::{Error, Result};

/// Syscalls the daemon allows after the seccomp filter installs.
///
/// Derived from `docs/v2/daemon-seccomp-envelope.md`.  Grouped by
/// purpose in the array literal so a reviewer can spot-check each
/// category against the source.  Names map 1:1 to `libc::SYS_*`
/// constants.
const ALLOWED_SYSCALLS: &[i64] = &[
    // ---- Unix-socket I/O ----
    // accept4 only — Rust's std::os::unix::net::UnixListener::accept
    // routes through accept4(2) (SOCK_CLOEXEC matters for the socket
    // FD that the daemon holds across many connections).  We omit
    // SYS_accept so a future code path that needs the older syscall
    // surfaces as a seccomp kill, not as a silent fallback.
    libc::SYS_accept4,
    libc::SYS_read,
    libc::SYS_write,
    libc::SYS_close,
    libc::SYS_shutdown,
    libc::SYS_recvfrom,
    libc::SYS_sendto,
    // ---- File system (rotation: wrapper materialise + cleanup) ----
    libc::SYS_openat,
    libc::SYS_unlinkat,
    libc::SYS_fchmod,
    // rename / renameat / renameat2 — emitted by
    // materialize_atomic (RENAME_EXCHANGE) and by the
    // honey/stale list tempfile + rename pattern.  Older Rust
    // std implementations call `rename`; newer ones call
    // `renameat`; our explicit nix::fcntl::renameat2 call
    // emits SYS_renameat2.  All three live in the allowlist
    // so the materialise path is portable across kernel /
    // libc combinations.
    libc::SYS_rename,
    libc::SYS_renameat,
    libc::SYS_renameat2,
    // rmdir — std::fs::remove_dir_all on the staging directory
    // after the atomic swap (post-swap staging holds the
    // previous epoch's wrappers, which we unlinkat-then-rmdir).
    libc::SYS_rmdir,
    // chmod (path-based) — std::fs::set_permissions emits this for
    // the freshly-written wrapper files (0o755).  Could be refactored
    // to OpenOptions::mode() + skip the chmod call but that's a
    // core-crate change deferred to v2.1.
    libc::SYS_chmod,
    libc::SYS_newfstatat,
    libc::SYS_statx,
    // fstat — emitted by std::fs::metadata on opened file descriptors
    // and by std::fs::File::metadata() in the rotation cleanup path.
    libc::SYS_fstat,
    libc::SYS_getdents64,
    // mkdir — std::fs::create_dir_all on the parent directory of the
    // honey-list / stale-list paths when they live under
    // /run/babbleon/.  Returns EEXIST if the dir already exists,
    // which is the common case after the first rotation.
    libc::SYS_mkdir,
    // fcntl — Rust std uses F_DUPFD_CLOEXEC on accept4'd sockets to
    // remap their FD numbers above the standard FD range.  Cannot
    // be elided without forking std.
    libc::SYS_fcntl,
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
    // ---- Randomness (HashMap re-seed during rotation build) ----
    libc::SYS_getrandom,
    // ---- Exit ----
    libc::SYS_exit,
    libc::SYS_exit_group,
    libc::SYS_rseq,
];

/// Apply `PR_SET_NO_NEW_PRIVS = 1` then install the daemon's seccomp
/// allowlist on the current thread.
///
/// # Errors
///
/// Returns [`Error::Ipc`] if either step fails.  We reuse the Ipc
/// variant to keep the daemon's error surface small; the Display
/// string carries the specific failure name (`PR_SET_NO_NEW_PRIVS`
/// vs. `seccomp filter build`/`compile`/`apply`) so log triage is
/// unambiguous.
///
/// # Failure semantics
///
/// The function returns `Err` on any step failure and the daemon
/// `main` propagates that as a fatal startup error — seccomp is
/// on by default, and silently running unfiltered would defeat
/// the secure default.
/// The kernel rejects unprivileged seccomp install only when
/// `PR_SET_NO_NEW_PRIVS` is not set; we set it as step 1 so
/// barring kernel-config anomalies the apply always succeeds.
pub fn apply() -> Result<()> {
    // Step 1: PR_SET_NO_NEW_PRIVS = 1.  Unprivileged operation;
    // monotonic (once on, can't be turned off).  Required for
    // unprivileged seccomp install.
    set_no_new_privs().map_err(|e| {
        Error::Ipc(format!("PR_SET_NO_NEW_PRIVS=1 (prctl): {e}"))
    })?;

    // Step 2: compile and install the allowlist.
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    for &nr in ALLOWED_SYSCALLS {
        rules.insert(nr, vec![]);
    }

    let arch = std::env::consts::ARCH
        .try_into()
        .unwrap_or(seccompiler::TargetArch::x86_64);

    let filter = SeccompFilter::new(
        rules,
        // Mismatch (default) action — what to do for a syscall NOT
        // in the allowlist.  KillProcess > Errno > Trap: the kernel
        // terminates immediately, giving the operator a clear
        // `dmesg` entry and refusing to let an exploit retry with
        // different arguments.
        SeccompAction::KillProcess,
        // Match action — what to do for a syscall ON the allowlist.
        SeccompAction::Allow,
        arch,
    )
    .map_err(|e| Error::Ipc(format!("seccomp filter build: {e}")))?;

    let prog: BpfProgram = filter
        .try_into()
        .map_err(|e| Error::Ipc(format!("seccomp filter compile: {e}")))?;

    seccompiler::apply_filter(&prog)
        .map_err(|e| Error::Ipc(format!("seccomp filter apply: {e}")))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::ALLOWED_SYSCALLS;

    #[test]
    fn allowlist_includes_socket_io() {
        assert!(ALLOWED_SYSCALLS.contains(&libc::SYS_accept4));
        assert!(ALLOWED_SYSCALLS.contains(&libc::SYS_read));
        assert!(ALLOWED_SYSCALLS.contains(&libc::SYS_write));
        assert!(ALLOWED_SYSCALLS.contains(&libc::SYS_close));
    }

    #[test]
    fn allowlist_includes_rotation_fs_calls() {
        // Per docs/v2/daemon-seccomp-envelope.md stage B' — these are
        // the calls the wrapper materialise path issues.
        assert!(ALLOWED_SYSCALLS.contains(&libc::SYS_openat));
        assert!(ALLOWED_SYSCALLS.contains(&libc::SYS_unlinkat));
        assert!(ALLOWED_SYSCALLS.contains(&libc::SYS_fchmod));
        assert!(ALLOWED_SYSCALLS.contains(&libc::SYS_getdents64));
    }

    #[test]
    fn allowlist_includes_exit_family() {
        assert!(ALLOWED_SYSCALLS.contains(&libc::SYS_exit));
        assert!(ALLOWED_SYSCALLS.contains(&libc::SYS_exit_group));
    }

    #[test]
    fn allowlist_excludes_execve_family() {
        // The daemon never execs.  An execve(2) attempt is a strong
        // signal of a compromise spawning a shell.
        assert!(!ALLOWED_SYSCALLS.contains(&libc::SYS_execve));
        assert!(!ALLOWED_SYSCALLS.contains(&libc::SYS_execveat));
    }

    #[test]
    fn allowlist_excludes_fork_family() {
        // Daemon is single-process by design.  Multi-thread future
        // (mapping-pre-build worker) will need clone + clone3
        // added; not in phase 2.
        assert!(!ALLOWED_SYSCALLS.contains(&libc::SYS_fork));
        assert!(!ALLOWED_SYSCALLS.contains(&libc::SYS_vfork));
        assert!(!ALLOWED_SYSCALLS.contains(&libc::SYS_clone));
        assert!(!ALLOWED_SYSCALLS.contains(&libc::SYS_clone3));
    }

    #[test]
    fn allowlist_excludes_socket_bind_in_steady_state() {
        // Bind + listen happen in startup BEFORE the filter
        // installs.  Forbidding them in steady state guarantees the
        // daemon cannot open a second outbound channel.
        assert!(!ALLOWED_SYSCALLS.contains(&libc::SYS_socket));
        assert!(!ALLOWED_SYSCALLS.contains(&libc::SYS_bind));
        assert!(!ALLOWED_SYSCALLS.contains(&libc::SYS_listen));
        assert!(!ALLOWED_SYSCALLS.contains(&libc::SYS_connect));
    }

    #[test]
    fn allowlist_excludes_privilege_escalation_surface() {
        // Reviewer-facing assertion: every commonly-abused privilege
        // syscall MUST stay off the allowlist.  If a refactor
        // accidentally adds one, this test trips immediately.
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
        // The envelope doc enumerates 40 syscalls:
        //   - 32 from the initial draft.
        //   - 4 added after the first strace pass (chmod, fstat,
        //     mkdir, fcntl — see "Strace confirmation").
        //   - 4 added for atomic wrapper-dir swap (rename,
        //     renameat, renameat2, rmdir — see
        //     materialize_atomic).
        //
        // If the list here drifts, either the doc is stale or the
        // implementation is.  Update both in the same PR.
        assert_eq!(
            ALLOWED_SYSCALLS.len(),
            40,
            "allowlist drifted from docs/v2/daemon-seccomp-envelope.md \
             (36 documented; this code lists {}).  Update both.",
            ALLOWED_SYSCALLS.len(),
        );
    }
}
