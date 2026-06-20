//! FIDO2 / WebAuthn hmac-secret KEK backend.
//!
//! Uses the CTAP2 hmac-secret extension to derive a per-host secret bound
//! to a specific authenticator (YubiKey, Solokey, etc).  Touch required;
//! private key never leaves the token.
//!
//! Compiled only with `--features fido2`.  See TODO.md for the
//! get_assertion / PIN / multi-authenticator items.

use crate::errors::{BabbleonError, Result};
use crate::vault::backend::KekBackend;

/// Per-vault hmac-secret salt.  32 random bytes hex-encoded; baked at
/// vault-init and stored in the vault header (it's safe in the clear —
/// the authenticator's secret is the real key).
pub const SALT_LEN: usize = 32;

pub struct Fido2Backend {
    /// Vault-bound salt, hex-encoded.  The token returns hmac(secret, salt)
    /// as the derived KEK.
    pub salt_hex: String,
}

impl Fido2Backend {
    pub fn new(salt_hex: String) -> Self {
        Self { salt_hex }
    }
}

impl KekBackend for Fido2Backend {
    fn derive_age_passphrase(&self, _credential: Option<&str>) -> Result<String> {
        #[cfg(feature = "fido2")]
        {
            // Real wire-up:
            //   1. Discover authenticators via authenticator-rs
            //   2. PublicKeyCredentialRequestOptions with extensions: hmac-secret
            //   3. Salt = self.salt_hex (32-byte hex)
            //   4. get_assertion → take hmac_secret output, hex-encode → KEK
            //   5. PIN prompt via callback if required
            Err(BabbleonError::HardwareUnavailable(
                "fido2 backend: get_assertion flow lands in M2".into(),
            ))
        }
        #[cfg(not(feature = "fido2"))]
        {
            Err(BabbleonError::HardwareUnavailable(
                "fido2 backend: rebuild babbleon with --features fido2".into(),
            ))
        }
    }

    fn name(&self) -> &'static str {
        "fido2"
    }
}
