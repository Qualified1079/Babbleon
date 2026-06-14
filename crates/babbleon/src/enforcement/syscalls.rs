//! Isolated Linux syscall wrappers (via `nix`).
//!
//! ALL kernel calls live here. Other enforcement modules never use `nix`
//! directly; this keeps the audit surface for privileged operations small.

#![cfg(target_os = "linux")]

use crate::errors::{BabbleonError, Result};
use nix::mount::{mount, umount2, MntFlags, MsFlags};
use nix::sched::{unshare, CloneFlags};
use std::path::Path;

#[allow(dead_code)] // used by ns-helper in M3
pub fn do_unshare(flags: CloneFlags) -> Result<()> {
    unshare(flags).map_err(|e| BabbleonError::Enforcement(format!("unshare: {e}")))
}

pub fn make_root_private() -> Result<()> {
    mount(
        Some("none"),
        "/",
        None::<&Path>,
        MsFlags::MS_PRIVATE | MsFlags::MS_REC,
        None::<&Path>,
    )
    .map_err(|e| BabbleonError::Enforcement(format!("make root private: {e}")))
}

pub fn mount_tmpfs(target: &Path, data: &str) -> Result<()> {
    mount(
        Some("tmpfs"),
        target,
        Some("tmpfs"),
        MsFlags::empty(),
        Some(data),
    )
    .map_err(|e| BabbleonError::Enforcement(format!("mount tmpfs {}: {e}", target.display())))
}

pub fn bind_mount(source: &Path, target: &Path) -> Result<()> {
    mount(
        Some(source),
        target,
        None::<&Path>,
        MsFlags::MS_BIND,
        None::<&Path>,
    )
    .map_err(|e| {
        BabbleonError::Enforcement(format!(
            "bind {} -> {}: {e}",
            source.display(),
            target.display()
        ))
    })
}

pub fn mount_proc_hidepid(target: &Path) -> Result<()> {
    mount(
        Some("proc"),
        target,
        Some("proc"),
        MsFlags::empty(),
        Some("hidepid=2"),
    )
    .map_err(|e| BabbleonError::Enforcement(format!("/proc hidepid: {e}")))
}

pub fn force_unmount(target: &Path) -> Result<()> {
    umount2(target, MntFlags::MNT_FORCE)
        .map_err(|e| BabbleonError::Enforcement(format!("umount {}: {e}", target.display())))
}
