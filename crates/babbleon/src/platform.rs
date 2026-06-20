//! Single source of truth for platform detection.
//!
//! All platform branching in the codebase should call helpers here, not
//! `cfg!` directly. cfg-based compilation gating IS allowed in modules that
//! are entirely platform-specific (e.g. `enforcement::linux_ns`).

use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Linux,
    MacOS,
    Windows,
    Other,
}

pub fn current() -> Platform {
    if cfg!(target_os = "linux") {
        Platform::Linux
    } else if cfg!(target_os = "macos") {
        Platform::MacOS
    } else if cfg!(target_os = "windows") {
        Platform::Windows
    } else {
        Platform::Other
    }
}

pub fn is_linux() -> bool {
    matches!(current(), Platform::Linux)
}

pub fn is_macos() -> bool {
    matches!(current(), Platform::MacOS)
}

/// True when /proc/self/ns/mnt is readable — necessary for unshare workflows.
pub fn has_unshare() -> bool {
    is_linux() && Path::new("/proc/self/ns/mnt").exists()
}

pub fn has_proc_fs() -> bool {
    Path::new("/proc/self/status").exists()
}

/// Best-effort parse of `uname -r` into (major, minor, patch).
pub fn kernel_version() -> (u32, u32, u32) {
    if !is_linux() {
        return (0, 0, 0);
    }
    let release = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default();
    let head = release.split('-').next().unwrap_or("").trim();
    let mut parts = head.split('.').map(|p| p.parse::<u32>().unwrap_or(0));
    (
        parts.next().unwrap_or(0),
        parts.next().unwrap_or(0),
        parts.next().unwrap_or(0),
    )
}

/// Landlock requires Linux kernel >= 5.13.
pub fn supports_landlock() -> bool {
    is_linux() && kernel_version() >= (5, 13, 0)
}

/// eBPF-LSM requires kernel >= 5.7 AND lsm=...,bpf in /proc/cmdline.
pub fn supports_ebpf_lsm() -> bool {
    if !is_linux() || kernel_version() < (5, 7, 0) {
        return false;
    }
    let cmdline = std::fs::read_to_string("/proc/cmdline").unwrap_or_default();
    cmdline.contains("lsm=") && cmdline.contains("bpf")
}

/// Probe for tpm2-tools presence (used by the TPM backend's subprocess fallback).
pub fn has_tpm2_tools() -> bool {
    which::which_in("tpm2_getcap", std::env::var_os("PATH"), "/").is_ok()
}

/// Minimal `which` replacement to avoid pulling in the `which` crate.
mod which {
    use std::ffi::OsString;
    use std::path::PathBuf;

    pub enum WhichErr {
        NotFound,
    }

    pub fn which_in<P: AsRef<std::ffi::OsStr>>(
        name: &str,
        path_var: Option<OsString>,
        _cwd: P,
    ) -> Result<PathBuf, WhichErr> {
        let path = path_var.unwrap_or_default();
        for dir in std::env::split_paths(&path) {
            let candidate = dir.join(name);
            if candidate.exists() {
                return Ok(candidate);
            }
        }
        Err(WhichErr::NotFound)
    }
}
