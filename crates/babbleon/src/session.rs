//! High-level orchestration: init / unlock / rotate.

use crate::errors::{BabbleonError, Result};
use crate::events::{Event, EventBus};
use crate::manifest::DEFAULT_TRACKED;
use crate::mapping::{Mapper, MappingTable};
use crate::storage::{ensure_dirs, vault_path};
use crate::vault::{SoftBackend, Vault, VaultPayload};
use std::path::{Path, PathBuf};

pub struct Session {
    pub payload: VaultPayload,
    pub mapping: MappingTable,
    pub tracked: Vec<String>,
    pub bus: EventBus,
    vault_file: PathBuf,
}

impl Session {
    pub fn initialize(
        password: &str,
        tracked: Option<Vec<String>>,
        vault_file: Option<PathBuf>,
    ) -> Result<Self> {
        ensure_dirs()?;
        let tracked = tracked.unwrap_or_else(default_tracked);
        let path = vault_file.unwrap_or_else(vault_path);
        if path.exists() {
            return Err(BabbleonError::Vault(format!(
                "vault already exists at {}",
                path.display()
            )));
        }

        let payload = VaultPayload::new(0, vec![]);
        let secret = payload.host_secret()?;
        let table = Mapper::new(&secret).build_table(&tracked, 0);
        let payload = payload.with_honey(table.honey_names.clone());

        let vault = Vault::new(SoftBackend::default());
        let sealed = vault.seal(&payload, Some(password))?;
        std::fs::write(&path, &sealed)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }

        let bus = EventBus::new();
        bus.emit(Event::VaultSealed {
            epoch: 0,
            backend: "soft".into(),
        });

        Ok(Self {
            payload,
            mapping: table,
            tracked,
            bus,
            vault_file: path,
        })
    }

    pub fn unlock(
        password: &str,
        tracked: Option<Vec<String>>,
        vault_file: Option<PathBuf>,
    ) -> Result<Self> {
        let tracked = tracked.unwrap_or_else(default_tracked);
        let path = vault_file.unwrap_or_else(vault_path);
        if !path.exists() {
            return Err(BabbleonError::VaultNotFound(path.display().to_string()));
        }

        let bus = EventBus::new();
        let vault = Vault::new(SoftBackend::default());
        let data = std::fs::read(&path)?;
        let payload = match vault.unseal(&data, Some(password)) {
            Ok(p) => p,
            Err(e) => {
                bus.emit(Event::UnlockFailed {
                    epoch: 0,
                    backend: "soft".into(),
                });
                return Err(e);
            }
        };
        let secret = payload.host_secret()?;
        let table = Mapper::new(&secret).build_table(&tracked, payload.epoch);

        Ok(Self {
            payload,
            mapping: table,
            tracked,
            bus,
            vault_file: path,
        })
    }

    pub fn rotate(&mut self, password: &str) -> Result<u64> {
        let old = self.payload.epoch;
        let new = old + 1;
        let secret = self.payload.host_secret()?;
        let table = Mapper::new(&secret).build_table(&self.tracked, new);
        let payload = self.payload.clone().with_epoch(new).with_honey(table.honey_names.clone());

        let vault = Vault::new(SoftBackend::default());
        let sealed = vault.seal(&payload, Some(password))?;
        std::fs::write(&self.vault_file, &sealed)?;

        self.payload = payload;
        self.mapping = table;
        self.bus.emit(Event::RotationComplete { old_epoch: old, new_epoch: new });
        Ok(new)
    }

    pub fn vault_file(&self) -> &Path {
        &self.vault_file
    }
}

fn default_tracked() -> Vec<String> {
    DEFAULT_TRACKED.iter().map(|s| s.to_string()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_then_unlock() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().join("vault.age");
        let tracked: Vec<String> = ["curl", "ssh"].iter().map(|s| s.to_string()).collect();
        let s1 = Session::initialize("pw", Some(tracked.clone()), Some(vault.clone())).unwrap();
        let s2 = Session::unlock("pw", Some(tracked), Some(vault)).unwrap();
        assert_eq!(s1.mapping.scramble("curl"), s2.mapping.scramble("curl"));
        assert_eq!(s1.payload.epoch, 0);
        assert_eq!(s2.payload.epoch, 0);
    }

    #[test]
    fn rotate_bumps_epoch_and_remaps() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().join("vault.age");
        let tracked: Vec<String> = vec!["curl".to_string()];
        let mut s = Session::initialize("pw", Some(tracked.clone()), Some(vault.clone())).unwrap();
        let old = s.mapping.scramble("curl").unwrap().to_string();
        s.rotate("pw").unwrap();
        let new = s.mapping.scramble("curl").unwrap();
        assert_eq!(s.payload.epoch, 1);
        assert_ne!(old, new);

        // persisted
        let s2 = Session::unlock("pw", Some(tracked), Some(vault)).unwrap();
        assert_eq!(s2.payload.epoch, 1);
    }
}
