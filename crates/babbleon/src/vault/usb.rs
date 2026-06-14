//! USB keyfile KEK: 32-byte file + optional passphrase for 2FA.

use crate::errors::{BabbleonError, Result};
use crate::vault::backend::KekBackend;
use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

const SALT: &[u8] = b"babbleon-usb-v1";
const KEYFILE_SIZE: usize = 32;
const M_KIB: u32 = 46 * 1024;
const T_COST: u32 = 2;
const P_COST: u32 = 1;
const HASH_LEN: usize = 32;

pub struct UsbBackend {
    pub keyfile_path: PathBuf,
}

impl UsbBackend {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            keyfile_path: path.into(),
        }
    }

    pub fn generate_keyfile(path: &Path) -> Result<()> {
        let mut buf = [0u8; KEYFILE_SIZE];
        rand::thread_rng().fill_bytes(&mut buf);
        std::fs::write(path, buf)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }
}

impl KekBackend for UsbBackend {
    fn derive_age_passphrase(&self, credential: Option<&str>) -> Result<String> {
        if !self.keyfile_path.exists() {
            return Err(BabbleonError::Vault(format!(
                "keyfile not found: {}",
                self.keyfile_path.display()
            )));
        }
        let keyfile_bytes = std::fs::read(&self.keyfile_path)?;
        if keyfile_bytes.len() < KEYFILE_SIZE {
            return Err(BabbleonError::Vault(
                "keyfile too short; may be corrupt".into(),
            ));
        }

        let material = if let Some(password) = credential {
            let params = Params::new(M_KIB, T_COST, P_COST, Some(HASH_LEN))
                .map_err(|e| BabbleonError::Vault(format!("argon2 params: {e}")))?;
            let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
            let mut pw_raw = [0u8; HASH_LEN];
            argon
                .hash_password_into(password.as_bytes(), SALT, &mut pw_raw)
                .map_err(|e| BabbleonError::Vault(format!("argon2: {e}")))?;
            [keyfile_bytes, pw_raw.to_vec()].concat()
        } else {
            keyfile_bytes
        };

        let mut h = Sha256::new();
        h.update(&material);
        h.update(b"babbleon-usb-kek-v1");
        Ok(hex::encode(h.finalize()))
    }

    fn name(&self) -> &'static str {
        "usb"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::core::{Vault, VaultPayload};

    #[test]
    fn keyfile_only_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let kf = dir.path().join("key.bin");
        UsbBackend::generate_keyfile(&kf).unwrap();
        let v = Vault::new(UsbBackend::new(&kf));
        let payload = VaultPayload::new(0, vec![]);
        let sealed = v.seal(&payload, None).unwrap();
        let out = v.unseal(&sealed, None).unwrap();
        assert_eq!(out.host_secret_hex, payload.host_secret_hex);
    }

    #[test]
    fn keyfile_plus_password_2fa() {
        let dir = tempfile::tempdir().unwrap();
        let kf = dir.path().join("key.bin");
        UsbBackend::generate_keyfile(&kf).unwrap();
        let v = Vault::new(UsbBackend::new(&kf));
        let payload = VaultPayload::new(7, vec![]);
        let sealed = v.seal(&payload, Some("2fa-pw")).unwrap();
        let out = v.unseal(&sealed, Some("2fa-pw")).unwrap();
        assert_eq!(out.epoch, 7);
    }

    #[test]
    fn missing_keyfile_errors() {
        let v = Vault::new(UsbBackend::new("/nonexistent/keyfile"));
        let r = v.seal(&VaultPayload::new(0, vec![]), None);
        assert!(r.is_err());
    }
}
