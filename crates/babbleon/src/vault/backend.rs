//! KEK backend trait — the only contract `Vault` depends on.
//!
//! Enterprise backends (HSM, escrow-server, HashiCorp Vault, SCIM-backed)
//! implement this and ship in `babbleon-enterprise`.

use crate::Result;

/// Credential payload tier-specific:
///   Soft     -> passphrase
///   USB      -> optional 2FA passphrase
///   TPM      -> empty
///   FIDO2    -> empty (token handles auth)
///   HSM      -> backend-defined
pub trait KekBackend: Send + Sync {
    fn derive_age_passphrase(&self, credential: Option<&str>) -> Result<String>;
    fn name(&self) -> &'static str;
}
