//! Vault — seal and unseal a [`VaultPayload`] under a [`KekBackend`].
//!
//! # What this defeats
//!
//! The vault is the at-rest container for the per-host secret.  An
//! attacker who reads the vault file from disk (cold-boot capture,
//! backup snapshot, file-system probe by a non-root local process if
//! permissions allow) sees only ciphertext.  Without the operator's
//! credential they cannot reach the per-host secret; with the
//! credential, the attacker has already won at a higher layer
//! (TTY hijack, keylogger) and the vault is incidental.
//!
//! # Mechanism
//!
//! The cipher is `age` (RFC-recognisable, audited, widely-deployed)
//! in its passphrase mode (`Encryptor::with_user_passphrase`).  The
//! "passphrase" the age layer sees is the [`KekBackend`]-derived
//! string, NOT the operator's typed credential.  For the soft
//! backend this is the hex-encoded Argon2id output; for future
//! backends it is whatever stretching their hardware provides.
//!
//! [`Vault::seal`]:  build payload bytes → derive age passphrase →
//! `age::Encryptor` → ciphertext.
//!
//! [`Vault::unseal`]:  derive age passphrase → `age::Decryptor` →
//! payload bytes → [`VaultPayload::from_json_bytes`].
//!
//! The wrong-passphrase path lands as [`Error::WrongPassphrase`] —
//! distinct from the "ciphertext truncated" path
//! ([`Error::Unseal`]) so operators distinguish "typo" from "damage".
//!
//! # Threat model boundaries
//!
//! - **Defeats:** off-host vault-file read.
//! - **Does NOT defeat:** on-host live operator with the
//!   credential.  Once an attacker has the credential, the vault is
//!   designed to be unsealable (that's the operator path too).

use std::io::{Read, Write};

use age::secrecy::Secret;

use crate::backend::KekBackend;
use crate::errors::{Error, Result};
use crate::payload::VaultPayload;

/// Vault wrapper around a [`KekBackend`].
///
/// One instance per `(backend-type, profile)` tuple.  Construct
/// inline at the unlock site; do not stash a `Vault` in a long-lived
/// struct (the backend may carry sensitive parameters in some
/// future implementations).
pub struct Vault<B: KekBackend> {
    backend: B,
}

impl<B: KekBackend> Vault<B> {
    /// Construct a vault wrapper.
    #[must_use]
    pub fn new(backend: B) -> Self {
        Self { backend }
    }

    /// Borrow the backend (mostly for `name()` queries).
    #[must_use]
    pub fn backend(&self) -> &B {
        &self.backend
    }

    /// Seal a payload under the backend-derived age passphrase.
    /// Returns the age ciphertext bytes ready for write-to-disk.
    ///
    /// # Errors
    ///
    /// - [`Error::Seal`] from age I/O or the KDF.
    /// - Backend-specific errors from the [`KekBackend`].
    pub fn seal(
        &self,
        payload: &VaultPayload,
        credential: Option<&str>,
    ) -> Result<Vec<u8>> {
        let passphrase = self.backend.derive_age_passphrase(credential)?;
        let plaintext = payload.to_json_bytes()?;
        let encryptor =
            age::Encryptor::with_user_passphrase(Secret::new(passphrase));
        let mut out = Vec::new();
        let mut writer = encryptor
            .wrap_output(&mut out)
            .map_err(|e| Error::Seal(format!("age wrap: {e}")))?;
        writer
            .write_all(&plaintext)
            .map_err(|e| Error::Seal(format!("age write: {e}")))?;
        writer
            .finish()
            .map_err(|e| Error::Seal(format!("age finish: {e}")))?;
        Ok(out)
    }

    /// Unseal age ciphertext with the backend-derived age passphrase.
    ///
    /// # Errors
    ///
    /// - [`Error::WrongPassphrase`] if the passphrase fails the age
    ///   MAC check.  This is the operator-visible "typo" path.
    /// - [`Error::Unseal`] if the ciphertext is structurally damaged
    ///   (truncated, wrong format) or if the inner payload fails to
    ///   parse.  Distinct from `WrongPassphrase` so operators
    ///   distinguish typo from corruption.
    /// - [`Error::Schema`] if the unwrapped payload is a different
    ///   schema version than this build understands.
    /// - Backend-specific errors from the [`KekBackend`].
    pub fn unseal(
        &self,
        data: &[u8],
        credential: Option<&str>,
    ) -> Result<VaultPayload> {
        let passphrase = self.backend.derive_age_passphrase(credential)?;
        let decryptor = match age::Decryptor::new(data)
            .map_err(|e| Error::Unseal(format!("age decryptor: {e}")))?
        {
            age::Decryptor::Passphrase(d) => d,
            age::Decryptor::Recipients(_) => {
                return Err(Error::Unseal(
                    "vault is recipient-encrypted, not passphrase-encrypted"
                        .into(),
                ));
            }
        };
        let mut reader = decryptor
            .decrypt(&Secret::new(passphrase), None)
            .map_err(|_| Error::WrongPassphrase)?;
        let mut plaintext = Vec::new();
        reader
            .read_to_end(&mut plaintext)
            .map_err(|e| Error::Unseal(format!("age read: {e}")))?;
        VaultPayload::from_json_bytes(&plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::payload::PAYLOAD_HOST_SECRET_LEN;
    use crate::soft_backend::{SoftBackend, SoftProfile};
    use zeroize::Zeroizing;

    fn soft_headless() -> SoftBackend {
        // Faster tests — soft `Laptop` is ~250 ms per derivation.
        SoftBackend::with_profile(SoftProfile::Headless)
    }

    fn fixed_payload(byte: u8, epoch: u64) -> VaultPayload {
        VaultPayload::new(
            Zeroizing::new(vec![byte; PAYLOAD_HOST_SECRET_LEN]),
            epoch,
            "soft",
        )
        .unwrap()
    }

    #[test]
    fn seal_unseal_round_trip_recovers_payload() {
        let v = Vault::new(soft_headless());
        let p = fixed_payload(0x5A, 3);
        let sealed = v.seal(&p, Some("correct horse battery staple")).unwrap();
        let q = v.unseal(&sealed, Some("correct horse battery staple")).unwrap();
        assert_eq!(p.host_secret(), q.host_secret());
        assert_eq!(p.epoch(), q.epoch());
        assert_eq!(p.tier(), q.tier());
        assert_eq!(p.schema(), q.schema());
    }

    #[test]
    fn wrong_passphrase_returns_wrong_passphrase() {
        let v = Vault::new(soft_headless());
        let p = fixed_payload(0x33, 0);
        let sealed = v.seal(&p, Some("rightpass")).unwrap();
        // `unwrap_err` requires `T: Debug`; VaultPayload deliberately
        // does not impl Debug (security-baseline rule 3).  Match.
        match v.unseal(&sealed, Some("wrongpass")) {
            Err(Error::WrongPassphrase) => {}
            Err(other) => panic!("expected WrongPassphrase, got {other:?}"),
            Ok(_) => panic!("wrong passphrase must not unseal"),
        }
    }

    #[test]
    fn truncated_ciphertext_returns_unseal_not_wrong_passphrase() {
        let v = Vault::new(soft_headless());
        let p = fixed_payload(0x33, 0);
        let sealed = v.seal(&p, Some("pass")).unwrap();
        let truncated = &sealed[..sealed.len() / 2];
        match v.unseal(truncated, Some("pass")) {
            // Wrong-passphrase MUST be reserved for genuine wrong-cred
            // failures, NOT corrupted ciphertext.
            Err(Error::WrongPassphrase) => {
                panic!("truncated ciphertext must NOT map to WrongPassphrase");
            }
            Err(_) => {}
            Ok(_) => panic!("truncated ciphertext must not unseal"),
        }
    }

    #[test]
    fn no_passphrase_returns_input_error() {
        let v = Vault::new(soft_headless());
        let p = fixed_payload(0x01, 0);
        let r = v.seal(&p, None);
        assert!(matches!(r, Err(Error::Input(_))));
    }

    #[test]
    fn ciphertext_differs_from_plaintext_secret() {
        let v = Vault::new(soft_headless());
        let p = fixed_payload(0x42, 0);
        let sealed = v.seal(&p, Some("pass")).unwrap();
        // The plaintext secret is the byte 0x42 repeated 32 times; if
        // the ciphertext literally contained that run, encryption is
        // broken.
        let needle = [0x42u8; PAYLOAD_HOST_SECRET_LEN];
        assert!(
            !sealed.windows(needle.len()).any(|w| w == needle),
            "plaintext secret bytes appear verbatim in ciphertext"
        );
    }

    #[test]
    fn two_seals_with_same_input_differ_in_ciphertext() {
        // age uses a random nonce per encryption; same passphrase +
        // same plaintext must NOT produce identical ciphertext.
        let v = Vault::new(soft_headless());
        let p = fixed_payload(0x77, 0);
        let a = v.seal(&p, Some("pass")).unwrap();
        let b = v.seal(&p, Some("pass")).unwrap();
        assert_ne!(a, b, "deterministic ciphertext from age — encryption broken");
    }
}
