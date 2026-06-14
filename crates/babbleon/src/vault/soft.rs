//! Soft-tier KEK: Argon2id stretches a user passphrase into the age passphrase.
//!
//! Honest copy: raises cost of automated credential theft; not a defense
//! against persistent code execution.

use crate::errors::{BabbleonError, Result};
use crate::vault::backend::KekBackend;
use argon2::{Algorithm, Argon2, Params, Version};

const SALT: &[u8] = b"babbleon-soft-v1";
// REVIEW(manual): m=46MiB tuned for laptops; needs IoT profile (DEFERRED.md).
const M_KIB: u32 = 46 * 1024;
const T_COST: u32 = 2;
const P_COST: u32 = 1;
const HASH_LEN: usize = 32;

#[derive(Default)]
pub struct SoftBackend;

impl KekBackend for SoftBackend {
    fn derive_age_passphrase(&self, credential: Option<&str>) -> Result<String> {
        let password = credential
            .ok_or_else(|| BabbleonError::Vault("soft backend requires a passphrase".into()))?;
        let params = Params::new(M_KIB, T_COST, P_COST, Some(HASH_LEN))
            .map_err(|e| BabbleonError::Vault(format!("argon2 params: {e}")))?;
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut out = [0u8; HASH_LEN];
        argon
            .hash_password_into(password.as_bytes(), SALT, &mut out)
            .map_err(|e| BabbleonError::Vault(format!("argon2: {e}")))?;
        Ok(hex::encode(out))
    }

    fn name(&self) -> &'static str {
        "soft"
    }
}
