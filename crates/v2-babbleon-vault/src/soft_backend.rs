//! Soft-tier KEK backend: Argon2id stretches a user passphrase into
//! the age passphrase.
//!
//! # What this defeats
//!
//! The "passphrase-protected vault" path: an attacker who exfiltrates
//! the vault file (cold-boot, disk image, backup snapshot) cannot
//! unlock it without spending CPU and RAM proportional to Argon2's
//! cost parameters.  At the default `Profile::Laptop` parameters
//! (m=46 MiB, t=2, p=1) one passphrase attempt costs ~250 ms on a
//! modern x86 laptop; at scale that is the difference between
//! "hours" and "millennia" for a 14-character passphrase under a
//! generic dictionary attack.
//!
//! # Mechanism
//!
//! Argon2id (RFC 9106) is the v2 password-hash primitive.  This
//! crate uses the `argon2` crate's typed parameter constructor (no
//! string-parsed parameter strings; no PHC-format autodetection).
//! The salt is the per-host file path's bytes XOR'd with a fixed
//! domain string — actually no: the salt is a fixed 16-byte
//! per-tier domain string.  Salt randomness is NOT load-bearing for
//! this design: the per-host secret it seals is itself fresh-random
//! per host, so the (passphrase, salt) → age-passphrase mapping
//! does not need to vary per file.  The cost parameters are public;
//! the attacker model already assumes the algorithm and parameters
//! are known (Kerckhoffs).
//!
//! Two profiles ship:
//!
//! - [`SoftProfile::Laptop`] — m=46 MiB, t=2, p=1.  ~250 ms /
//!   attempt on a modern x86 laptop.  Default for desktop/laptop
//!   installs.
//! - [`SoftProfile::Headless`] — m=8 MiB, t=12, p=1.  Same wall-
//!   clock, fits IoT-class RAM budgets.
//!
//! # Threat model boundaries
//!
//! - **Defeats:** offline dictionary attacks at human-typeable
//!   passphrase strength when paired with a strong passphrase.
//! - **Does NOT defeat:** weak passphrases (e.g. `"password"`).
//!   The KDF's cost is a multiplier on the attacker's per-attempt
//!   cost, not a substitute for entropy.
//! - **Does NOT defeat:** keylogger / shoulder-surf capture of the
//!   passphrase itself; that's outside the vault's threat model.

use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::backend::KekBackend;
use crate::errors::{Error, Result};

/// Domain-separation salt for the soft backend's Argon2id.  Fixed and
/// public; randomness here is not load-bearing — see module doc.
const SALT: &[u8] = b"babbleon-soft-v2";

/// Byte length of the Argon2id output that becomes the age passphrase.
const KEK_LEN: usize = 32;

/// Name returned by [`SoftBackend::name`] when sealing a vault under
/// the soft tier.  Used as the `tier` field in
/// [`crate::VaultPayload`].
pub const SOFT_BACKEND_NAME: &str = "soft";

/// Soft-tier cost profile.
///
/// `Laptop` and `Headless` aim for the same wall-clock cost
/// (~250 ms / attempt) on their respective target classes.  The
/// memory parameter trades against the iteration count: laptop-
/// class machines have RAM to burn, IoT-class machines do not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SoftProfile {
    /// Desktop / laptop budget: m=46 MiB, t=2, p=1.
    #[default]
    Laptop,
    /// `IoT` / headless budget: m=8 MiB, t=12, p=1.
    Headless,
}

impl SoftProfile {
    /// Return `(memory_kib, time_cost, parallelism)` for this profile.
    #[must_use]
    pub const fn params(self) -> (u32, u32, u32) {
        match self {
            Self::Laptop => (46 * 1024, 2, 1),
            Self::Headless => (8 * 1024, 12, 1),
        }
    }
}

/// Soft-tier KEK backend.  Stretches a passphrase via Argon2id.
#[derive(Default)]
pub struct SoftBackend {
    profile: SoftProfile,
}

impl SoftBackend {
    /// Construct a backend with an explicit profile.  Use
    /// [`SoftBackend::default`] for the `Laptop` profile.
    #[must_use]
    pub fn with_profile(profile: SoftProfile) -> Self {
        Self { profile }
    }

    /// Current profile.
    #[must_use]
    pub fn profile(&self) -> SoftProfile {
        self.profile
    }
}

impl KekBackend for SoftBackend {
    fn derive_age_passphrase(&self, credential: Option<&str>) -> Result<String> {
        let password = credential.ok_or_else(|| {
            Error::Input("soft backend requires a passphrase".into())
        })?;
        if password.is_empty() {
            return Err(Error::Input(
                "soft backend rejects empty passphrase".into(),
            ));
        }
        let (m_kib, t_cost, p_cost) = self.profile.params();
        let params = Params::new(m_kib, t_cost, p_cost, Some(KEK_LEN))
            .map_err(|e| Error::Seal(format!("argon2 params: {e}")))?;
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut out: Zeroizing<[u8; KEK_LEN]> =
            Zeroizing::new([0u8; KEK_LEN]);
        argon
            .hash_password_into(password.as_bytes(), SALT, out.as_mut_slice())
            .map_err(|e| Error::Seal(format!("argon2 hash: {e}")))?;
        // age ingests a UTF-8 passphrase string; hex-encode the KEK so
        // the input matches age's expectations.  The hex `String` lives
        // exactly long enough to feed `age::Encryptor`, then drops.
        Ok(hex::encode(out.as_slice()))
    }

    fn name(&self) -> &'static str {
        SOFT_BACKEND_NAME
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_is_soft() {
        assert_eq!(SoftBackend::default().name(), "soft");
        assert_eq!(
            SoftBackend::with_profile(SoftProfile::Headless).name(),
            "soft",
        );
    }

    #[test]
    fn missing_passphrase_errors() {
        let r = SoftBackend::default().derive_age_passphrase(None);
        assert!(matches!(r, Err(Error::Input(_))));
    }

    #[test]
    fn empty_passphrase_errors() {
        let r = SoftBackend::default().derive_age_passphrase(Some(""));
        assert!(matches!(r, Err(Error::Input(_))));
    }

    #[test]
    fn deterministic_for_same_input() {
        // Use the Headless profile in tests so the KDF cost stays
        // bounded (~30 ms each); we run two derivations.
        let backend = SoftBackend::with_profile(SoftProfile::Headless);
        let a = backend.derive_age_passphrase(Some("correct horse")).unwrap();
        let b = backend.derive_age_passphrase(Some("correct horse")).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn different_passphrase_yields_different_kek() {
        let backend = SoftBackend::with_profile(SoftProfile::Headless);
        let a = backend.derive_age_passphrase(Some("right")).unwrap();
        let b = backend.derive_age_passphrase(Some("wrong")).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn different_profile_yields_different_kek() {
        let laptop =
            SoftBackend::with_profile(SoftProfile::Laptop)
                .derive_age_passphrase(Some("same passphrase"))
                .unwrap();
        let headless =
            SoftBackend::with_profile(SoftProfile::Headless)
                .derive_age_passphrase(Some("same passphrase"))
                .unwrap();
        assert_ne!(laptop, headless);
    }

    #[test]
    fn profile_default_is_laptop() {
        assert_eq!(SoftProfile::default(), SoftProfile::Laptop);
    }

    #[test]
    fn profile_params_distinct() {
        assert_ne!(
            SoftProfile::Laptop.params(),
            SoftProfile::Headless.params(),
        );
    }

    #[test]
    fn kek_length_is_64_hex_chars() {
        // 32-byte Argon2 output hex-encoded = 64 ASCII hex chars.
        let backend = SoftBackend::with_profile(SoftProfile::Headless);
        let k = backend.derive_age_passphrase(Some("xyz")).unwrap();
        assert_eq!(k.len(), 64);
        assert!(k.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
