//! Linux mount + PID namespace driver.
//!
//! All kernel calls flow through `syscalls.rs`.  This module has zero `nix`
//! imports — keeps the namespace orchestration auditable without reading the
//! nix API.
//!
//! # Trust-tier detection
//!
//! After setup, the driver records the *trusted* mount-namespace inode
//! (`/proc/self/ns/mnt`).  Any process that presents the trusted namespace
//! inode is treated as trusted; all others see the scrambled view.  This is
//! more robust than an env-var cookie (defeated by env scrape) or a PID-tree
//! walk (racy).  The inode is stored in `/run/babbleon/trusted-ns-inode`
//! so wrapper scripts can read it without privilege.

#![cfg(target_os = "linux")]

use super::driver::{EnforcementDriver, EnforcementResult};
use super::syscalls;
use super::view::View;
use crate::errors::{BabbleonError, Result};
use crate::mapping::MappingTable;
use std::collections::HashMap;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

const RUN_DIR: &str = "/run/babbleon";
const TRUSTED_NS_FILE: &str = "/run/babbleon/trusted-ns-inode";

pub struct LinuxNamespaceDriver {
    /// Root of the tmpfs that holds scrambled bind-mount stubs.
    pub scrambled_root: PathBuf,
    /// Root where the trusted (real-name) view lives; usually the real $PATH dir.
    pub trusted_root: PathBuf,
    /// Home directory for credential gating.  None = skip credential gate.
    pub home: Option<PathBuf>,
    /// Optional dir of pre-generated wrapper scripts keyed by scrambled name.
    /// If set, the driver bind-mounts the wrapper instead of the real binary —
    /// this is what enables banner-deception + trust-tier checks.
    pub wrapper_root: Option<PathBuf>,
    /// Active mounts we need to tear down in reverse order.
    mounts: Vec<PathBuf>,
    /// Inode of /proc/self/ns/mnt at the time we set up the trusted namespace.
    trusted_ns_inode: Option<u64>,
}

impl LinuxNamespaceDriver {
    pub fn new(scrambled_root: PathBuf, trusted_root: PathBuf) -> Self {
        let home = std::env::var_os("HOME").map(PathBuf::from);
        Self {
            scrambled_root,
            trusted_root,
            home,
            wrapper_root: None,
            mounts: Vec::new(),
            trusted_ns_inode: None,
        }
    }

    /// Set the wrapper directory; subsequent `present_untrusted` calls will
    /// bind-mount `wrapper_root/<scrambled>` instead of the raw real binary.
    pub fn with_wrappers(mut self, wrapper_root: PathBuf) -> Self {
        self.wrapper_root = Some(wrapper_root);
        self
    }
}

impl Default for LinuxNamespaceDriver {
    fn default() -> Self {
        Self::new(
            PathBuf::from("/run/babbleon/scrambled"),
            PathBuf::from("/usr/local/bin"),
        )
    }
}

impl EnforcementDriver for LinuxNamespaceDriver {
    fn name(&self) -> &'static str {
        "linux-ns"
    }

    /// Present the trusted view: real names, no scrambling, real binary paths.
    /// Records the current mount-NS inode so wrapper scripts can detect tier.
    fn present_trusted(
        &mut self,
        real_root: &Path,
        tracked: &[String],
    ) -> Result<EnforcementResult> {
        // Snapshot the trusted NS inode.
        let inode = ns_mnt_inode()?;
        self.trusted_ns_inode = Some(inode);

        // Write it to /run so wrappers can read it without privilege.
        std::fs::create_dir_all(RUN_DIR)
            .map_err(|e| BabbleonError::Enforcement(format!("create {RUN_DIR}: {e}")))?;
        std::fs::write(TRUSTED_NS_FILE, inode.to_string())
            .map_err(|e| BabbleonError::Enforcement(format!("write trusted-ns-inode: {e}")))?;

        let view = View::trusted(tracked, real_root);
        Ok(EnforcementResult {
            tier: "trusted".into(),
            visible: view.entries,
            notes: vec![format!(
                "trusted pass-through {}; ns-inode={}",
                real_root.display(),
                inode
            )],
        })
    }

    /// Present the untrusted (scrambled) view inside a fresh mount namespace.
    ///
    /// Expects to be called *after* the ns-helper has already called
    /// `unshare(NEWNS|NEWPID)` and `make_root_private()`.  If those haven't
    /// happened we still try — worst case the bind-mounts leak to the host,
    /// which is caught by `make_root_private()` re-running here.
    fn present_untrusted(
        &mut self,
        real_root: &Path,
        mapping: &MappingTable,
    ) -> Result<EnforcementResult> {
        std::fs::create_dir_all(RUN_DIR)
            .map_err(|e| BabbleonError::Enforcement(format!("create {RUN_DIR}: {e}")))?;
        std::fs::create_dir_all(&self.scrambled_root)
            .map_err(|e| BabbleonError::Enforcement(format!("mkdir scrambled root: {e}")))?;

        // Belt-and-suspenders: mark root private so host doesn't see our mounts.
        syscalls::make_root_private()?;

        // tmpfs on our scrambled root: contents exist only in this NS.
        syscalls::mount_tmpfs(&self.scrambled_root, "mode=0555")?;
        self.mounts.push(self.scrambled_root.clone());

        // Bind-mount the wrapper (if configured) or the real binary under
        // its scrambled name.  Bind-mounting the wrapper is what makes the
        // tier-detection + banner-deception layer actually fire on exec.
        let mut visible: HashMap<String, PathBuf> = HashMap::new();
        for (real, scrambled) in &mapping.real_to_scrambled {
            let src = match &self.wrapper_root {
                Some(wrap_dir) => {
                    let wp = wrap_dir.join(scrambled);
                    if wp.exists() {
                        wp
                    } else {
                        // Wrapper missing — fall back to real binary so the
                        // scrambled view still has *something* at that name.
                        real_root.join(real)
                    }
                }
                None => real_root.join(real),
            };
            if !src.exists() {
                continue;
            }
            let dst = self.scrambled_root.join(scrambled);
            // Create a plain file as the bind-mount target.
            std::fs::write(&dst, b"").map_err(|e| {
                BabbleonError::Enforcement(format!("create stub {}: {e}", dst.display()))
            })?;
            syscalls::bind_mount(&src, &dst)?;
            self.mounts.push(dst.clone());
            visible.insert(scrambled.clone(), dst);
        }

        // /proc with hidepid=2 — only meaningful inside a PID NS.
        match syscalls::mount_proc_hidepid(Path::new("/proc")) {
            Ok(()) => tracing::debug!("/proc remounted hidepid=2"),
            Err(e) => tracing::warn!("/proc hidepid remount failed (PID NS not set up?): {e}"),
        }

        // Gate credential directories: overlay each with an empty tmpfs so
        // the path exists (avoids telltale "no such file" errors) but leaks nothing.
        let mut gated_creds = 0usize;
        if let Some(home) = &self.home.clone() {
            match crate::credentials::apply_untrusted_gate(home) {
                Ok(gated) => {
                    gated_creds = gated.len();
                    self.mounts.extend(gated);
                }
                Err(e) => tracing::warn!("credential gate failed: {e}"),
            }
        }

        let count = visible.len();
        Ok(EnforcementResult {
            tier: "untrusted".into(),
            visible,
            notes: vec![format!(
                "{count} bind-mounts at {}; {gated_creds} cred dirs gated; scrambled view active",
                self.scrambled_root.display()
            )],
        })
    }

    fn teardown(&mut self) -> Result<()> {
        for path in self.mounts.drain(..).rev() {
            if let Err(e) = syscalls::force_unmount(&path) {
                tracing::warn!("teardown umount {}: {e}", path.display());
            }
        }
        // Best-effort: remove the trusted-NS-inode file.
        let _ = std::fs::remove_file(TRUSTED_NS_FILE);
        Ok(())
    }
}

/// Returns true if the calling process is in the trusted mount namespace.
/// Used by wrapper scripts (via the file) and by the driver itself.
pub fn in_trusted_ns() -> bool {
    let Ok(inode) = ns_mnt_inode() else {
        return false;
    };
    let Ok(content) = std::fs::read_to_string(TRUSTED_NS_FILE) else {
        return false;
    };
    content.trim().parse::<u64>() == Ok(inode)
}

fn ns_mnt_inode() -> Result<u64> {
    std::fs::metadata("/proc/self/ns/mnt")
        .map(|m| m.ino())
        .map_err(|e| BabbleonError::Enforcement(format!("stat /proc/self/ns/mnt: {e}")))
}
