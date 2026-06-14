//! seccomp-bpf filter for the untrusted tier.
//!
//! Applied in the child process *after* the ns-helper has exec'd it.
//! Denies the syscalls that let a process spy on or inject into others.

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

pub fn apply_untrusted_filter() -> Result<()> {
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
