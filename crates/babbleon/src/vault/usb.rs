//! USB keyfile KEK: 32-byte file + optional passphrase for 2FA.

use crate::errors::{BabbleonError, Result};
use crate::vault::backend::KekBackend;
use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

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
        // Keyfile bytes are KEK material — wipe on drop.  Also wipe the
        // password-stretched bytes and the concatenated material buffer
        // we feed into the final SHA-256.
        let keyfile_bytes = Zeroizing::new(std::fs::read(&self.keyfile_path)?);
        if keyfile_bytes.len() < KEYFILE_SIZE {
            return Err(BabbleonError::Vault(
                "keyfile too short; may be corrupt".into(),
            ));
        }

        let material: Zeroizing<Vec<u8>> = if let Some(password) = credential {
            let params = Params::new(M_KIB, T_COST, P_COST, Some(HASH_LEN))
                .map_err(|e| BabbleonError::Vault(format!("argon2 params: {e}")))?;
            let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
            let mut pw_raw: Zeroizing<[u8; HASH_LEN]> = Zeroizing::new([0u8; HASH_LEN]);
            argon
                .hash_password_into(password.as_bytes(), SALT, pw_raw.as_mut_slice())
                .map_err(|e| BabbleonError::Vault(format!("argon2: {e}")))?;
            let mut combined = Vec::with_capacity(keyfile_bytes.len() + HASH_LEN);
            combined.extend_from_slice(&keyfile_bytes);
            combined.extend_from_slice(pw_raw.as_slice());
            Zeroizing::new(combined)
        } else {
            // Already in a Zeroizing; clone the bytes into a fresh one
            // so the surrounding code shape stays the same.
            Zeroizing::new(keyfile_bytes.to_vec())
        };

        let mut h = Sha256::new();
        h.update(material.as_slice());
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

    #[test]
    fn wrong_password_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let kf = dir.path().join("key.bin");
        UsbBackend::generate_keyfile(&kf).unwrap();
        let v = Vault::new(UsbBackend::new(&kf));
        let payload = VaultPayload::new(1, vec![]);
        let sealed = v.seal(&payload, Some("correct-pw")).unwrap();
        let r = v.unseal(&sealed, Some("wrong-pw"));
        assert!(r.is_err());
    }

    #[test]
    fn keyfile_without_password_differs_from_keyfile_with_password() {
        let dir = tempfile::tempdir().unwrap();
        let kf = dir.path().join("key.bin");
        UsbBackend::generate_keyfile(&kf).unwrap();
        let b = UsbBackend::new(&kf);
        let kek_no_pw = b.derive_age_passphrase(None).unwrap();
        let kek_with_pw = b.derive_age_passphrase(Some("extra")).unwrap();
        assert_ne!(kek_no_pw, kek_with_pw);
    }

    #[test]
    fn two_different_keyfiles_produce_different_keks() {
        let dir = tempfile::tempdir().unwrap();
        let kf1 = dir.path().join("key1.bin");
        let kf2 = dir.path().join("key2.bin");
        UsbBackend::generate_keyfile(&kf1).unwrap();
        UsbBackend::generate_keyfile(&kf2).unwrap();
        let kek1 = UsbBackend::new(&kf1).derive_age_passphrase(None).unwrap();
        let kek2 = UsbBackend::new(&kf2).derive_age_passphrase(None).unwrap();
        assert_ne!(kek1, kek2, "distinct keyfiles must produce distinct KEKs");
    }
}
