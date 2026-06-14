//! Soft-tier KEK: Argon2id stretches a user passphrase into the age passphrase.
//!
//! Honest copy: raises cost of automated credential theft; not a defense
//! against persistent code execution.
//!
//! Two profiles ship:
//!   `Profile::Laptop`  — m=46 MiB, t=2, p=1   (default; ~250 ms on a modern laptop)
//!   `Profile::Headless` — m=8 MiB,  t=12, p=1 (same wall-time, fits IoT/server RAM)
//!
//! The profile is stored in the vault header so future unlocks pick the
//! right parameters automatically.

use crate::errors::{BabbleonError, Result};
use crate::vault::backend::KekBackend;
use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};

const SALT: &[u8] = b"babbleon-soft-v1";
const HASH_LEN: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum Profile {
    #[default]
    Laptop,
    Headless,
}

impl Profile {
    fn params(self) -> (u32, u32, u32) {
        match self {
            Profile::Laptop => (46 * 1024, 2, 1),
            Profile::Headless => (8 * 1024, 12, 1),
        }
    }
}

#[derive(Default)]
pub struct SoftBackend {
    pub profile: Profile,
}

impl SoftBackend {
    pub fn with_profile(profile: Profile) -> Self {
        Self { profile }
    }
}

impl KekBackend for SoftBackend {
    fn derive_age_passphrase(&self, credential: Option<&str>) -> Result<String> {
        let password = credential
            .ok_or_else(|| BabbleonError::Vault("soft backend requires a passphrase".into()))?;
        let (m_kib, t_cost, p_cost) = self.profile.params();
        let params = Params::new(m_kib, t_cost, p_cost, Some(HASH_LEN))
            .map_err(|e| BabbleonError::Vault(format!("argon2 params: {e}")))?;
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut out = [0u8; HASH_LEN];
        argon
            .hash_password_into(password.as_bytes(), SALT, &mut out)
            .map_err(|e| BabbleonError::Vault(format!("argon2: {e}")))?;
        Ok(hex::encode(out))
    }

    fn name(&self) -> &'static str {
        match self.profile {
            Profile::Laptop => "soft",
            Profile::Headless => "soft-headless",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profiles_produce_different_outputs() {
        let laptop = SoftBackend::with_profile(Profile::Laptop)
            .derive_age_passphrase(Some("same-pw"))
            .unwrap();
        let headless = SoftBackend::with_profile(Profile::Headless)
            .derive_age_passphrase(Some("same-pw"))
            .unwrap();
        assert_ne!(
            laptop, headless,
            "different Argon2 params must produce different KEKs"
        );
    }

    #[test]
    fn missing_passphrase_errors() {
        let r = SoftBackend::default().derive_age_passphrase(None);
        assert!(r.is_err());
    }
}
