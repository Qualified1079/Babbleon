//! Linux mount + PID namespace driver.
//!
//! All syscalls flow through `syscalls.rs`. This module has zero `nix`
//! imports — keeps the namespace orchestration easy to read.

#![cfg(target_os = "linux")]

use super::driver::{EnforcementDriver, EnforcementResult};
use super::syscalls;
use super::view::View;
use crate::errors::Result;
use crate::mapping::MappingTable;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

pub struct LinuxNamespaceDriver {
    pub scrambled_root: PathBuf,
    mounts: Vec<PathBuf>,
}

impl Default for LinuxNamespaceDriver {
    fn default() -> Self {
        Self {
            scrambled_root: PathBuf::from("/var/lib/babbleon/scrambled"),
            mounts: Vec::new(),
        }
    }
}

impl EnforcementDriver for LinuxNamespaceDriver {
    fn name(&self) -> &'static str {
        "linux-ns"
    }

    fn present_trusted(&mut self, real_root: &Path, tracked: &[String]) -> Result<EnforcementResult> {
        let view = View::trusted(tracked, real_root);
        Ok(EnforcementResult {
            tier: "trusted".into(),
            visible: view.entries,
            notes: vec![format!("trusted: pass-through {}", real_root.display())],
        })
    }

    fn present_untrusted(&mut self, real_root: &Path, mapping: &MappingTable) -> Result<EnforcementResult> {
        std::fs::create_dir_all(&self.scrambled_root)?;

        // mark our NS private so mounts don't leak to host
        syscalls::make_root_private()?;
        syscalls::mount_tmpfs(&self.scrambled_root, "mode=0755")?;
        self.mounts.push(self.scrambled_root.clone());

        let mut visible: HashMap<String, PathBuf> = HashMap::new();
        for (real, scrambled) in &mapping.real_to_scrambled {
            let src = real_root.join(real);
            if !src.exists() {
                continue;
            }
            let dst = self.scrambled_root.join(scrambled);
            std::fs::File::create(&dst)?;
            syscalls::bind_mount(&src, &dst)?;
            self.mounts.push(dst.clone());
            visible.insert(scrambled.clone(), dst);
        }

        // hidepid only meaningful inside a fresh PID NS; tolerate failure here
        // and rely on the helper binary to have set up the PID NS properly.
        let _ = syscalls::mount_proc_hidepid(Path::new("/proc"));

        let count = visible.len();
        Ok(EnforcementResult {
            tier: "untrusted".into(),
            visible,
            notes: vec![format!(
                "{} bind mounts at {}",
                count,
                self.scrambled_root.display()
            )],
        })
    }

    fn teardown(&mut self) -> Result<()> {
        // best-effort; namespace exit handles real cleanup
        for path in self.mounts.drain(..).rev() {
            let _ = syscalls::force_unmount(&path);
        }
        Ok(())
    }
}
