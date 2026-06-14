//! Enforcement subsystem: presents the right view of `$PATH` to each tier.
//!
//! # The attack this defeats
//!
//! An attacker with code execution in a session does two things to figure
//! out what's worth attacking next:
//!
//!   1. Enumerates `$PATH` to learn what tools are available (`ls`, shell
//!      completion, scripted reconnaissance).
//!   2. Probes those tools (`--help`, `--version`) to fingerprint their
//!      versions, vendor, and config.
//!
//! Babbleon's enforcement layer makes (1) return scrambled names that
//! don't match any wordlist, and (2) return banner text for a different
//! tool entirely.  The attacker's enumeration outputs become structured
//! lies, not silence — silence would leak that the wrapper exists.
//!
//! # Module map
//!
//!   - `driver`     — the trait two implementations must satisfy.
//!   - `view`       — the per-tier name → real-path catalog.
//!   - `simulated`  — no-op driver for tests / non-Linux platforms.
//!   - `linux_ns`   — the production driver (mount + PID namespaces).
//!   - `wrapper`    — the unified shell template (tier-check + tripwire).
//!   - `seccomp`    — process-inspection syscall deny-list.
//!   - `landlock`   — filesystem allowlist (LSM, defense-in-depth).
//!   - `ebpf`       — exec-guard via BPF LSM (kernel 6.1+).
//!   - `syscalls`   — the single audit point for every nix/libc call.
//!   - `factory`    — driver selection at startup.

pub mod driver;
pub mod factory;
pub mod simulated;
pub mod view;
pub mod wrapper;

pub mod ebpf;
#[cfg(target_os = "linux")]
pub mod landlock;
#[cfg(target_os = "linux")]
pub mod linux_ns;
#[cfg(target_os = "linux")]
pub mod seccomp;
#[cfg(target_os = "linux")]
pub(crate) mod syscalls;

pub use driver::{EnforcementDriver, EnforcementResult};
pub use simulated::SimulatedDriver;
pub use view::View;
