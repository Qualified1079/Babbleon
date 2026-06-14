//! Vault payload + seal/unseal using age passphrase encryption.

use crate::errors::{BabbleonError, Result};
use crate::vault::backend::KekBackend;
use age::secrecy::Secret;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultPayload {
    pub epoch: u64,
    /// 32-byte secret as hex.
    pub host_secret_hex: String,
    #[serde(default)]
    pub honey_names: Vec<String>,
}

impl VaultPayload {
    pub fn new(epoch: u64, honey_names: Vec<String>) -> Self {
        let mut secret = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut secret);
        Self {
            epoch,
            host_secret_hex: hex::encode(secret),
            honey_names,
        }
    }

    pub fn host_secret(&self) -> Result<Vec<u8>> {
        hex::decode(&self.host_secret_hex)
            .map_err(|e| BabbleonError::Vault(format!("invalid host_secret hex: {e}")))
    }

    pub fn with_epoch(mut self, epoch: u64) -> Self {
        self.epoch = epoch;
        self
    }

    pub fn with_honey(mut self, honey_names: Vec<String>) -> Self {
        self.honey_names = honey_names;
        self
    }
}

pub struct Vault<B: KekBackend> {
    pub backend: B,
}

impl<B: KekBackend> Vault<B> {
    pub fn new(backend: B) -> Self {
        Self { backend }
    }

    pub fn seal(&self, payload: &VaultPayload, credential: Option<&str>) -> Result<Vec<u8>> {
        let passphrase = self.backend.derive_age_passphrase(credential)?;
        let plaintext = serde_json::to_vec(payload)?;
        let encryptor = age::Encryptor::with_user_passphrase(Secret::new(passphrase));

        let mut out = Vec::new();
        let mut writer = encryptor
            .wrap_output(&mut out)
            .map_err(|e| BabbleonError::AgeEncrypt(e.to_string()))?;
        writer
            .write_all(&plaintext)
            .map_err(|e| BabbleonError::AgeEncrypt(e.to_string()))?;
        writer
            .finish()
            .map_err(|e| BabbleonError::AgeEncrypt(e.to_string()))?;
        Ok(out)
    }

    pub fn unseal(&self, data: &[u8], credential: Option<&str>) -> Result<VaultPayload> {
        let passphrase = self.backend.derive_age_passphrase(credential)?;
        let decryptor = match age::Decryptor::new(data)
            .map_err(|e| BabbleonError::AgeDecrypt(e.to_string()))?
        {
            age::Decryptor::Passphrase(d) => d,
            _ => {
                return Err(BabbleonError::Vault(
                    "vault is not passphrase-encrypted".into(),
                ))
            }
        };
        let mut reader = decryptor
            .decrypt(&Secret::new(passphrase), None)
            .map_err(|_| BabbleonError::WrongPassphrase)?;

        let mut plaintext = Vec::new();
        reader
            .read_to_end(&mut plaintext)
            .map_err(|e| BabbleonError::AgeDecrypt(e.to_string()))?;
        let payload: VaultPayload = serde_json::from_slice(&plaintext)?;
        Ok(payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::soft::SoftBackend;

    #[test]
    fn seal_unseal_roundtrip() {
        let v = Vault::new(SoftBackend::default());
        let payload = VaultPayload::new(3, vec!["a".into(), "b".into()]);
        let sealed = v
            .seal(&payload, Some("correct horse battery staple"))
            .unwrap();
        let out = v
            .unseal(&sealed, Some("correct horse battery staple"))
            .unwrap();
        assert_eq!(out.epoch, 3);
        assert_eq!(out.host_secret_hex, payload.host_secret_hex);
        assert_eq!(out.honey_names, vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn wrong_passphrase_rejected() {
        let v = Vault::new(SoftBackend::default());
        let payload = VaultPayload::new(0, vec![]);
        let sealed = v.seal(&payload, Some("rightpass")).unwrap();
        let err = v.unseal(&sealed, Some("wrongpass")).unwrap_err();
        matches!(err, BabbleonError::WrongPassphrase);
    }
}
