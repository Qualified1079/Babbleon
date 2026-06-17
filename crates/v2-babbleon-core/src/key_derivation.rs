//! HKDF-SHA-256 sub-key derivation per (epoch, purpose) tuple.
//!
//! # What this defeats
//!
//! v1 used `SHA-256(host_secret || label)` for domain separation
//! between purposes (identifier mapping, honey names, padding, etc).
//! Hand-rolled hash-of-concat is functionally fine for our use but
//! is not the audit-recognisable primitive auditors expect for
//! domain separation.  HKDF (RFC 5869) is.
//!
//! v2 derives every per-purpose sub-key with `HKDF-SHA-256`:
//!
//!   sub_key = HKDF-Expand(HKDF-Extract(salt=epoch_bytes,
//!                                      ikm=host_secret),
//!                          info=purpose_label,
//!                          length=L)
//!
//! - **ikm** (input keying material) — the 32-byte per-host secret.
//! - **salt** — the 8-byte big-endian epoch counter.  Including the
//!   epoch in the salt (not in the info) means rotation produces a
//!   fresh extract output, not just a fresh expand output.  This
//!   matches HKDF's design intent.
//! - **info** — the purpose label as bytes, e.g.
//!   `b"v2-identifier-mapping"`.  Distinct labels per purpose
//!   prevent cross-purpose key reuse.
//! - **L** — the requested output length in bytes; HKDF supports up
//!   to 255 × 32 = 8 160 bytes per call.
//!
//! # Threat model boundaries
//!
//! - Defeats: cross-purpose key-reuse attacks (purpose-1 ciphertext
//!   does not leak information about purpose-2 keys).
//! - Defeats: cross-epoch related-key attacks (epoch-N derivations
//!   are statistically independent from epoch-M derivations under
//!   the PRF assumption on HMAC-SHA-256).
//! - Does NOT defeat: attacks on the underlying SHA-256 PRF
//!   (would break HMAC, HKDF, and every other modern KDF
//!   simultaneously).
//!
//! # Purpose labels in use
//!
//! Each v2 component declares its purpose labels at module top so
//! grep finds them all in one place.  Current labels:
//!
//!   `permutation::PURPOSE_IDENTIFIER`  → identifier wordlist
//!                                        permutation
//!   `permutation::PURPOSE_HONEY`       → honey-name wordlist
//!                                        permutation
//!   `wrapper::PURPOSE_PADDING`         → per-wrapper SHA-256
//!                                        padding seed
//!
//! All labels are byte strings prefixed `b"v2-..."` so the v2 KDF
//! tree is disjoint from any future v3 derivations using the same
//! host secret.

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::errors::{Error, Result};
use crate::per_host_secret::PerHostSecret;

/// Derive a sub-key of `length` bytes for the given `(epoch, purpose)`.
///
/// Output is wrapped in `Zeroizing<Vec<u8>>` so the bytes are wiped
/// when the caller drops the returned buffer.
///
/// # Errors
///
/// - `Error::Crypto` if HKDF's expand step fails (only possible if
///   `length` exceeds 255 × HashLen = 8 160 bytes for SHA-256).
pub fn derive_subkey(
    secret: &PerHostSecret,
    epoch: u64,
    purpose: &[u8],
    length: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    let salt = epoch.to_be_bytes();
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), secret.expose());
    let mut out = Zeroizing::new(vec![0u8; length]);
    hkdf.expand(purpose, out.as_mut_slice())
        .map_err(|e| Error::Crypto(format!("HKDF-Expand: {e}")))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::derive_subkey;
    use crate::per_host_secret::PerHostSecret;

    fn fixed_secret() -> PerHostSecret {
        PerHostSecret::from_bytes(&[0x42; 32]).unwrap()
    }

    #[test]
    fn deterministic_for_same_inputs() {
        let s = fixed_secret();
        let a = derive_subkey(&s, 0, b"purpose-1", 32).unwrap();
        let b = derive_subkey(&s, 0, b"purpose-1", 32).unwrap();
        assert_eq!(a.as_slice(), b.as_slice());
    }

    #[test]
    fn different_purpose_yields_different_key() {
        let s = fixed_secret();
        let a = derive_subkey(&s, 0, b"purpose-1", 32).unwrap();
        let b = derive_subkey(&s, 0, b"purpose-2", 32).unwrap();
        assert_ne!(a.as_slice(), b.as_slice());
    }

    #[test]
    fn different_epoch_yields_different_key() {
        let s = fixed_secret();
        let a = derive_subkey(&s, 0, b"purpose-1", 32).unwrap();
        let b = derive_subkey(&s, 1, b"purpose-1", 32).unwrap();
        assert_ne!(a.as_slice(), b.as_slice());
    }

    #[test]
    fn different_secret_yields_different_key() {
        let s1 = PerHostSecret::from_bytes(&[0x01; 32]).unwrap();
        let s2 = PerHostSecret::from_bytes(&[0x02; 32]).unwrap();
        let a = derive_subkey(&s1, 0, b"purpose-1", 32).unwrap();
        let b = derive_subkey(&s2, 0, b"purpose-1", 32).unwrap();
        assert_ne!(a.as_slice(), b.as_slice());
    }

    #[test]
    fn variable_length_outputs_supported() {
        let s = fixed_secret();
        let short = derive_subkey(&s, 0, b"x", 16).unwrap();
        let long = derive_subkey(&s, 0, b"x", 64).unwrap();
        assert_eq!(short.len(), 16);
        assert_eq!(long.len(), 64);
        // First 16 bytes of the long output match the short — HKDF
        // expand is a streaming construction.
        assert_eq!(short.as_slice(), &long.as_slice()[..16]);
    }

    #[test]
    fn excessive_length_returns_error() {
        let s = fixed_secret();
        // SHA-256 HKDF cap is 255 * 32 = 8160 bytes.
        let err = derive_subkey(&s, 0, b"x", 8161).unwrap_err();
        assert!(matches!(err, crate::errors::Error::Crypto(_)));
    }
}
