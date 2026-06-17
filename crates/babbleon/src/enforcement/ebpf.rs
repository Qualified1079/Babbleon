//! eBPF-LSM enforcement layer (Linux 5.7+ with CONFIG_BPF_LSM=y).
//!
//! This module detects whether the running kernel has BPF LSM enabled and
//! provides a typed interface for loading enforcement programs.  The actual
//! BPF bytecode is generated at build time (see `build.rs`) and embedded as
//! bytes.  On kernels without BPF LSM the module degrades gracefully —
//! mount-NS + seccomp remain the primary defense.
//!
//! # What BPF LSM adds
//!
//! seccomp can block syscalls but cannot inspect *arguments* portably.
//! BPF LSM hooks into `bprm_check_security` (pre-exec) and
//! `file_open` to enforce:
//!   1. Untrusted-tier processes cannot open paths under the real tool root
//!      (e.g. `/usr/bin/curl`).  They only see the scrambled wrapper dir.
//!   2. An untrusted-tier process that somehow learns a real path still hits
//!      an `EACCES` at the LSM hook before the kernel even starts the binary.
//!
//! # Current status
//!
//! The BPF programs (`.bpf.c` sources) are compiled by `tools/ebpf/` and
//! embedded as `UNTRUSTED_EXEC_GUARD_BPF` bytes.  Until that build step is
//! wired (M3.5+), the embedded bytes are a zero-length placeholder and the
//! module falls back to detection-only mode.

#[cfg(target_os = "linux")]
mod inner {
    use crate::errors::{BabbleonError, Result};
    use std::path::Path;

    /// Outcome of a BPF LSM availability probe.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum BpfLsmStatus {
        /// BPF LSM is active; we can load programs.
        Available,
        /// Kernel too old (< 5.7) or CONFIG_BPF_LSM not set.
        Unavailable { reason: String },
        /// Kernel has BPF LSM but the calling process lacks CAP_BPF / CAP_SYS_ADMIN.
        PermissionDenied,
    }

    /// Minimum kernel version we'll load BPF LSM programs on.
    ///
    /// 6.1 LTS has the worst pre-6.0 BPF verifier CVEs patched and is the
    /// first kernel where `bpf_link` semantics for LSM programs are stable.
    /// Older kernels degrade to mount-NS + seccomp + Landlock only.
    pub const MIN_KERNEL: (u32, u32) = (6, 1);

    /// Parse `major.minor` from `/proc/sys/kernel/osrelease`.
    pub fn kernel_version() -> Option<(u32, u32)> {
        let s = std::fs::read_to_string("/proc/sys/kernel/osrelease").ok()?;
        let mut parts = s.trim().split(['.', '-']);
        let major: u32 = parts.next()?.parse().ok()?;
        let minor: u32 = parts.next()?.parse().ok()?;
        Some((major, minor))
    }

    fn kernel_meets_minimum() -> bool {
        match kernel_version() {
            Some((maj, min)) => (maj, min) >= MIN_KERNEL,
            None => false,
        }
    }

    /// Probe the kernel for BPF LSM support without loading any program.
    ///
    /// Checks (in order):
    ///   1. Kernel >= MIN_KERNEL (refuses older kernels to dodge verifier CVEs).
    ///   2. `/sys/kernel/security/lsm` contains "bpf".
    ///   3. A `BPF_PROG_TYPE_LSM` feature probe via `bpf(BPF_BTF_LOAD, ...)`.
    pub fn probe() -> BpfLsmStatus {
        // Kernel version gate — refuse to touch BPF on pre-6.1 kernels even
        // if the lsm= line claims bpf is active.
        if !kernel_meets_minimum() {
            let kver = kernel_version_string();
            return BpfLsmStatus::Unavailable {
                reason: format!(
                    "kernel {kver} below minimum {}.{} — BPF LSM disabled to avoid \
                     pre-{}.{} verifier CVE exposure; mount-NS + seccomp + Landlock \
                     remain active",
                    MIN_KERNEL.0, MIN_KERNEL.1, MIN_KERNEL.0, MIN_KERNEL.1
                ),
            };
        }

        // Quick check via lsm file — available since 5.1
        let lsm_active = std::fs::read_to_string("/sys/kernel/security/lsm")
            .map(|s| s.split(',').any(|l| l.trim() == "bpf"))
            .unwrap_or(false);

        if !lsm_active {
            let kver = kernel_version_string();
            return BpfLsmStatus::Unavailable {
                reason: format!(
                    "BPF not listed in /sys/kernel/security/lsm (kernel {kver}); \
                     boot with lsm=...,bpf or enable CONFIG_BPF_LSM"
                ),
            };
        }

        // BPF feature probe: try BPF_BTF_LOAD (cmd=18) with a zero-length blob.
        // EINVAL → kernel has BPF but our blob is bad (expected — BPF available).
        // EPERM  → no privilege.
        // ENOSYS → old kernel.
        const BPF_BTF_LOAD: libc::c_long = 18;
        // SAFETY: `syscall(2)` is the documented C variadic that dispatches
        // to the kernel.  We pass `SYS_bpf` (a valid syscall number on
        // every supported architecture), the BPF command number, a NULL
        // attribute pointer, and a zero size.  A NULL+0 input is rejected
        // by the kernel with EINVAL or similar — never dereferenced — so
        // passing a null pointer is correct, not a violation.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_bpf,
                BPF_BTF_LOAD,
                std::ptr::null::<libc::c_void>(),
                0usize,
            )
        };
        let errno = if rc < 0 {
            // SAFETY: `__errno_location` returns a per-thread errno pointer
            // valid for the thread's lifetime; reading immediately after a
            // syscall is the documented contract.
            unsafe { *libc::__errno_location() }
        } else {
            0
        };

        match errno {
            libc::EPERM => BpfLsmStatus::PermissionDenied,
            libc::ENOSYS => BpfLsmStatus::Unavailable {
                reason: "bpf(2) syscall not available (kernel too old)".into(),
            },
            // EINVAL / EFAULT / other: BPF is present, probe blob was rejected as expected
            _ => BpfLsmStatus::Available,
        }
    }

    /// Handle returned by a loaded BPF LSM program.
    ///
    /// Holds the program FD and the BPF *link* FD (created via
    /// `BPF_LINK_CREATE`, not pinned to `/sys/fs/bpf/`).  Because the link is
    /// FD-anchored, the kernel auto-detaches the program when this process
    /// exits — even on SIGKILL — so a crashed loader cannot leave a dangling
    /// deny-all program attached to `bprm_check_security`.
    ///
    /// We deliberately do *not* pin to bpffs.  Pins survive process death and
    /// would require a separate cleanup tool to recover from a bad load.
    #[derive(Debug)]
    pub struct BpfLsmHandle {
        /// File descriptor of the loaded BPF program.
        fd: i32,
        /// File descriptor of the BPF link (BPF_LINK_CREATE, never pinned).
        link_fd: i32,
    }

    impl Drop for BpfLsmHandle {
        fn drop(&mut self) {
            // Close link first so the program is detached before the prog FD goes.
            if self.link_fd >= 0 {
                // SAFETY: `close(2)` takes a valid fd we own and returns an
                // int; no aliasing, no lifetime concern.  We own this fd
                // (handed to us at `BPF_LINK_CREATE` time) and Drop runs at
                // most once per handle, so we cannot close it twice.
                unsafe { libc::close(self.link_fd) };
            }
            if self.fd >= 0 {
                // SAFETY: as above.
                unsafe { libc::close(self.fd) };
            }
        }
    }

    /// Load the untrusted-exec-guard BPF LSM program.
    ///
    /// The embedded bytecode hooks `bprm_check_security`.  It reads the calling
    /// process's mount-NS inode from the task struct and, if it does not match
    /// the trusted-NS inode written to a BPF map at setup time, denies
    /// execution of any path outside the scrambled wrapper dir.
    ///
    /// Safety properties:
    ///   - Kernel-version gated: refuses to load below MIN_KERNEL.
    ///   - Link-based attachment (BPF_LINK_CREATE), never pinned to bpffs —
    ///     SIGKILL of the loader auto-detaches the program.
    ///   - Caller (babbleon-ns-helper) drops CAP_BPF + CAP_SYS_ADMIN immediately
    ///     after this returns.
    ///
    /// Returns `Err` if BPF LSM is unavailable, the kernel is too old, the
    /// bytecode is empty (not yet compiled), or loading fails.
    pub fn load_exec_guard(
        _trusted_ns_inode: u64,
        _scrambled_root: &Path,
    ) -> Result<BpfLsmHandle> {
        // Kernel gate — refuse to load on pre-MIN_KERNEL even if BPF appears available.
        if !kernel_meets_minimum() {
            return Err(BabbleonError::Enforcement(format!(
                "kernel below {}.{}; refusing to load BPF LSM program. \
                 mount-NS + seccomp + Landlock remain active.",
                MIN_KERNEL.0, MIN_KERNEL.1
            )));
        }

        // Placeholder: BPF object bytes are not yet compiled.
        // When tools/ebpf/Makefile runs, it writes the compiled object here via
        // `include_bytes!` in a generated module.
        const EXEC_GUARD_BPF: &[u8] = &[];

        if EXEC_GUARD_BPF.is_empty() {
            return Err(BabbleonError::Enforcement(
                "BPF exec-guard bytecode not compiled; \
                 run `make -C tools/ebpf` to build it"
                    .into(),
            ));
        }

        // Real load path (runs when bytecode is available):
        // 1. bpf(BPF_BTF_LOAD, ...) to load BTF type info
        // 2. bpf(BPF_PROG_LOAD, BPF_PROG_TYPE_LSM, ...) to load the program
        // 3. bpf(BPF_LINK_CREATE, ...) to attach to bprm_check_security hook
        // 4. bpf(BPF_MAP_UPDATE_ELEM, ...) to populate the trusted-inode map
        //
        // This is intentionally left as stubs — the actual loading requires
        // BTF info from the compiled object which isn't available until the
        // BPF C source is compiled.  See tools/ebpf/README.md.
        Err(BabbleonError::Enforcement(
            "BPF exec-guard load path not yet implemented".into(),
        ))
    }

    fn kernel_version_string() -> String {
        std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .unwrap_or_else(|_| "unknown".into())
            .trim()
            .to_string()
    }
}

#[cfg(target_os = "linux")]
pub use inner::{kernel_version, load_exec_guard, probe, BpfLsmHandle, BpfLsmStatus, MIN_KERNEL};

/// Non-Linux stub: BPF LSM is Linux-only.
#[cfg(not(target_os = "linux"))]
pub mod stub {
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum BpfLsmStatus {
        Unavailable { reason: String },
    }
    pub fn probe() -> BpfLsmStatus {
        BpfLsmStatus::Unavailable {
            reason: "BPF LSM is Linux-only".into(),
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub use stub::{probe, BpfLsmStatus};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_returns_without_panic() {
        // We can't assert the specific outcome since it depends on the kernel,
        // but the probe must not panic or block indefinitely.
        let status = probe();
        match &status {
            BpfLsmStatus::Available => {
                println!("BPF LSM: available");
            }
            #[cfg(target_os = "linux")]
            BpfLsmStatus::PermissionDenied => {
                println!("BPF LSM: needs CAP_BPF");
            }
            BpfLsmStatus::Unavailable { reason } => {
                println!("BPF LSM: unavailable — {reason}");
            }
        }
        // probe() should never block; we just verify it returns
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn exec_guard_errors_when_bytecode_not_compiled() {
        use std::path::Path;
        let result = load_exec_guard(12345, Path::new("/run/babbleon/scrambled"));
        assert!(
            result.is_err(),
            "load_exec_guard should fail until BPF bytecode is compiled or on old kernel"
        );
        let msg = result.unwrap_err().to_string();
        // Either "kernel below" (old kernel gate) or "BPF/bpf" (no bytecode) is fine
        assert!(
            msg.contains("BPF") || msg.contains("bpf") || msg.contains("kernel"),
            "error should mention BPF or kernel gate: {msg}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn kernel_version_parses() {
        // Should not panic and should return Some on Linux
        let v = kernel_version();
        assert!(v.is_some(), "kernel_version() should parse osrelease");
        let (maj, _min) = v.unwrap();
        assert!(maj >= 3, "kernel major version sanity: got {maj}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn min_kernel_is_at_least_6_1() {
        // Lock in the gate — if someone lowers this, the test should catch it.
        assert!(
            MIN_KERNEL >= (6, 1),
            "MIN_KERNEL must be >= 6.1 to dodge pre-6.0 verifier CVEs; got {:?}",
            MIN_KERNEL
        );
    }
}
