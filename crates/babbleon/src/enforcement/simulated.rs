//! No-op driver: returns dict-style views without touching the kernel.

use super::driver::{EnforcementDriver, EnforcementResult};
use super::view::View;
use crate::mapping::MappingTable;
use crate::Result;
use std::path::Path;

#[derive(Default)]
pub struct SimulatedDriver;

impl EnforcementDriver for SimulatedDriver {
    fn name(&self) -> &'static str {
        "simulated"
    }

    fn present_trusted(&mut self, real_root: &Path, tracked: &[String]) -> Result<EnforcementResult> {
        let view = View::trusted(tracked, real_root);
        Ok(EnforcementResult {
            tier: "trusted".into(),
            visible: view.entries,
            notes: vec![format!("simulated trusted view over {}", real_root.display())],
        })
    }

    fn present_untrusted(&mut self, real_root: &Path, mapping: &MappingTable) -> Result<EnforcementResult> {
        let view = View::untrusted(mapping, real_root);
        let count = view.entries.len();
        Ok(EnforcementResult {
            tier: "untrusted".into(),
            visible: view.entries,
            notes: vec![
                format!("simulated untrusted view over {}", real_root.display()),
                format!("{} scrambled names", count),
            ],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mapping::Mapper;

    fn stub_root() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        for tool in ["curl", "ssh", "git"] {
            let p = bin.join(tool);
            std::fs::write(&p, "#!/bin/sh\n").unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
        }
        (dir, bin)
    }

    #[test]
    fn simulated_trusted_view() {
        let (_d, bin) = stub_root();
        let tracked = vec!["curl".to_string(), "ssh".to_string(), "git".to_string()];
        let mut driver = SimulatedDriver;
        let r = driver.present_trusted(&bin, &tracked).unwrap();
        assert_eq!(r.tier, "trusted");
        assert_eq!(r.visible.len(), 3);
    }

    #[test]
    fn simulated_untrusted_view() {
        let (_d, bin) = stub_root();
        let tracked: Vec<String> = ["curl", "ssh", "git"].iter().map(|s| s.to_string()).collect();
        let table = Mapper::new(&[5u8; 32]).build_table(&tracked, 0);
        let mut driver = SimulatedDriver;
        let r = driver.present_untrusted(&bin, &table).unwrap();
        assert_eq!(r.tier, "untrusted");
        for scrambled in r.visible.keys() {
            assert!(!tracked.contains(scrambled), "no canonical names should appear");
            assert!(table.reveal(scrambled).is_some());
        }
    }
}
