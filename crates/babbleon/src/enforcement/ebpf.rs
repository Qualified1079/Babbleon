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

    /// Probe the kernel for BPF LSM support without loading any program.
    ///
    /// Checks (in order):
    ///   1. `/sys/kernel/security/lsm` contains "bpf".
    ///   2. `/proc/sys/kernel/unprivileged_bpf_disabled` (informational).
    ///   3. A `BPF_PROG_TYPE_LSM` feature probe via `bpf(BPF_BTF_LOAD, ...)`.
    pub fn probe() -> BpfLsmStatus {
        // Quick check via lsm file — available since 5.1
        let lsm_active = std::fs::read_to_string("/sys/kernel/security/lsm")
            .map(|s| s.split(',').any(|l| l.trim() == "bpf"))
            .unwrap_or(false);

        if !lsm_active {
            // Try to distinguish "old kernel" from "BPF LSM not in boot params"
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
        let rc = unsafe {
            libc::syscall(
                libc::SYS_bpf,
                BPF_BTF_LOAD,
                std::ptr::null::<libc::c_void>(),
                0usize,
            )
        };
        let errno = if rc < 0 {
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

    /// Handle returned by a loaded BPF LSM program.  Dropping it unloads the program.
    #[derive(Debug)]
    pub struct BpfLsmHandle {
        /// File descriptor of the loaded BPF program.
        fd: i32,
        /// File descriptor of the BPF link attaching the program to the hook.
        link_fd: i32,
    }

    impl Drop for BpfLsmHandle {
        fn drop(&mut self) {
            if self.link_fd >= 0 {
                unsafe { libc::close(self.link_fd) };
            }
            if self.fd >= 0 {
                unsafe { libc::close(self.fd) };
            }
        }
    }

    /// Load the untrusted-exec-guard BPF LSM program.
    ///
    /// The embedded bytecode (`UNTRUSTED_EXEC_GUARD_BPF`) is a compiled
    /// BPF object that hooks `bprm_check_security`.  It reads the calling
    /// process's mount-NS inode from the task struct and, if it does not
    /// match the trusted-NS inode written to a BPF map at setup time, denies
    /// execution of any path outside the scrambled wrapper dir.
    ///
    /// Returns `Err` if BPF LSM is unavailable, the bytecode is empty
    /// (not yet compiled), or loading fails.
    pub fn load_exec_guard(
        _trusted_ns_inode: u64,
        _scrambled_root: &Path,
    ) -> Result<BpfLsmHandle> {
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
pub use inner::{load_exec_guard, probe, BpfLsmHandle, BpfLsmStatus};

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
            "load_exec_guard should fail until BPF bytecode is compiled"
        );
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("BPF") || msg.contains("bpf"),
            "error should mention BPF: {msg}"
        );
    }
}
