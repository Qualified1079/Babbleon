//! Babbleon v2 untrusted-tier launcher — library surface.
//!
//! # What this defeats
//!
//! v1 ships `babbleon-ns-helper` as `4755 root:root` (setuid-root).
//! A bug in the helper turns the full 41-capability root authority
//! into an exploit primitive: arbitrary mount, kernel-module load,
//! ptrace, BPF, etc.  v2 ships **file capabilities**, not setuid: the
//! launcher is granted only `CAP_SYS_ADMIN`, `CAP_SETUID`,
//! `CAP_SETGID`, and `CAP_IPC_LOCK` and drops each as soon as the
//! step that needs it has completed.  An attacker exploiting a
//! launcher bug gains at most those four capabilities, never the
//! other 37.
//!
//! # Mechanism — the 11-step lifecycle
//!
//! `docs/v2/least-privilege.md` documents the ordering verbatim.
//! Each step is its own module so a failure can be precisely
//! attributed and so reviewers can audit the privilege envelope at
//! each step in isolation:
//!
//! | Step | Module               | Capability consumed |
//! |------|----------------------|---------------------|
//! | 1    | (kernel-side)        | grants from file caps |
//! | 2    | [`bounding_set`]     | drops 37 unwanted bits |
//! | 3    | [`process_hardening`]| `CAP_IPC_LOCK` for `mlockall` |
//! | 4    | [`namespaces`]       | `CAP_SYS_ADMIN` for `unshare(NEWNS|NEWPID)` |
//! | 5    | [`namespaces`]       | `CAP_SYS_ADMIN` for `MS_PRIVATE` remount |
//! | 6    | [`mounts`]           | `CAP_SYS_ADMIN` for bind / tmpfs (post-unshare) |
//! | 7    | [`process_hardening::set_no_new_privs`] | none |
//! | 8    | [`seccomp_profile`]  | none (NNP allows unprivileged install) |
//! | 9    | [`identity_drop`]    | `CAP_SETUID` / `CAP_SETGID` |
//! | 10   | [`bounding_set::drop_all_bounding`] | none |
//! | 11   | (caller)             | none — `execve` of child |
//!
//! By step 10 the process holds NO capabilities and `NO_NEW_PRIVS`
//! is set, so the child cannot regain any capability even via file
//! caps on `execve`.
//!
//! # Threat model boundaries
//!
//! - Defeats: a launcher bug becoming root-equivalent.  An exploit
//!   restricted to the four capabilities cannot load kernel modules,
//!   attach a debugger, raw-socket-sniff, etc.
//! - Defeats: a child process re-acquiring any capability — `NNP=1`
//!   plus an empty bounding set forbids it.
//! - Does NOT defeat: kernel bugs in the syscalls the launcher
//!   itself invokes.  That layer is handled by the seccomp profile,
//!   the kernel-update cadence on the operator's host, and the
//!   "no `CAP_BPF` anywhere" stance in `docs/v2/least-privilege.md`.
//! - Does NOT defeat: an attacker who already has root.  Out of
//!   scope per the threat model.
//!
//! # Compartmentalization rationale
//!
//! Each lifecycle step is one module with one public function so a
//! failure raises a typed error attributable to a single step.  No
//! step depends on the address-space state of any other step — each
//! takes only its inputs and returns `Result<(), Error>`.
//!
//! `main.rs` is purely orchestration: parse arguments, run steps in
//! order, exit non-zero on the first failure with a step identifier
//! in the message.

#![cfg_attr(target_os = "linux", deny(unsafe_code))]
#![cfg_attr(not(target_os = "linux"), forbid(unsafe_code))]
#![deny(missing_docs)]
#![warn(clippy::pedantic)]

pub mod cli;
pub mod errors;
pub mod preflight;

#[cfg(target_os = "linux")]
pub mod activated_table_input;
#[cfg(target_os = "linux")]
pub mod bounding_set;
#[cfg(target_os = "linux")]
pub mod credential_gate;
#[cfg(target_os = "linux")]
pub mod identity_drop;
#[cfg(target_os = "linux")]
pub mod mounts;
#[cfg(target_os = "linux")]
pub mod namespaces;
#[cfg(target_os = "linux")]
pub mod process_hardening;
#[cfg(target_os = "linux")]
pub mod seccomp_profile;
#[cfg(target_os = "linux")]
pub mod syscall;

pub use cli::Args;
pub use errors::{Error, Result, Step};
