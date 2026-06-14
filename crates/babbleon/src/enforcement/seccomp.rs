//! seccomp-bpf filter for the untrusted tier.
//!
//! Applied in the child process *after* the ns-helper has exec'd it.
//!
//! # What this defeats
//!
//! A compromised untrusted-tier process otherwise has many ways to leak
//! information *out* of its namespace by inspecting peer processes:
//!
//!   - `ptrace` — attach to a sibling and read memory directly.
//!   - `process_vm_readv` / `process_vm_writev` — cross-process memory peek
//!     without ptrace's attach semantics; the textbook namespace escape.
//!   - `kcmp` — compare file descriptors / NS handles across PIDs; lets the
//!     attacker confirm "am I in the same mount NS as PID X?".
//!   - `pidfd_*` — modern handle-based peer manipulation; lets the attacker
//!     hold a stable reference even when PIDs are recycled.
//!   - `perf_event_open` — side-channel via hardware counters; can recover
//!     kernel pointers and timing-leak secrets from sibling processes.
//!   - `bpf` — load programs into the kernel; an untrusted tier loading
//!     BPF is a privilege-escalation primitive, full stop.
//!   - `userfaultfd` — defers page faults to userspace; well-known kernel
//!     race-condition primitive (Dirty Pipe / FUSE-style races).
//!
//! Denying these is the *minimal* deny-list — every entry corresponds to a
//! published exploit class, not speculative hardening.

#![cfg(target_os = "linux")]

use crate::errors::{BabbleonError, Result};
use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, SeccompRule};
use std::collections::BTreeMap;

const DENIED_SYSCALLS: &[i64] = &[
    libc::SYS_ptrace,
    libc::SYS_process_vm_readv,
    libc::SYS_process_vm_writev,
    libc::SYS_kcmp,
    libc::SYS_pidfd_open,
    libc::SYS_pidfd_getfd,
    libc::SYS_pidfd_send_signal,
    libc::SYS_perf_event_open,
    libc::SYS_bpf,
    libc::SYS_userfaultfd,
];

/// Install the deny-list as a seccomp-bpf filter on the calling thread.
///
/// Idempotent: applying twice is harmless because seccomp filters chain.
/// Returns an error if the kernel rejects the filter (e.g. unsupported
/// architecture); the caller must decide whether that's fatal.
pub fn block_process_inspection_syscalls() -> Result<()> {
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    for &nr in DENIED_SYSCALLS {
        rules.insert(nr, vec![]);
    }

    let arch = std::env::consts::ARCH
        .try_into()
        .unwrap_or(seccompiler::TargetArch::x86_64);

    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::KillProcess,
        arch,
    )
    .map_err(|e| BabbleonError::Enforcement(format!("seccomp build: {e}")))?;

    let prog: BpfProgram = filter
        .try_into()
        .map_err(|e| BabbleonError::Enforcement(format!("seccomp compile: {e}")))?;

    seccompiler::apply_filter(&prog)
        .map_err(|e| BabbleonError::Enforcement(format!("seccomp apply: {e}")))
}
