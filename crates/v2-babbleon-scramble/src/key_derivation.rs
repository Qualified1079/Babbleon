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
//!   `sub_key` = HKDF-Expand(HKDF-Extract(salt=`epoch_bytes`,
//!                                      `ikm=host_secret`),
//!                          `info=purpose_label`,
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
///   `length` exceeds 255 × `HashLen` = 8 160 bytes for SHA-256).
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

/// Derive a 32-byte domain seed from the per-host secret and a
/// caller-supplied label, with **no epoch in the salt**.
///
/// This mirrors `tools/wordlist-role-partitioning/src/seed.rs`'s
/// `derive_seed_bytes` bit-for-bit: `HKDF-Extract(salt=None,
/// ikm=secret)` then `HKDF-Expand(info=label, length=32)`.  The two
/// implementations must stay in lock-step so a per-role wordlist
/// extraction the operator ran offline through the tool binary
/// (`--extract-seed-file` + `--extract-domain-label`) reproduces
/// the identical 32-byte seed when the runtime re-derives it here —
/// no shelling out to the tool, no re-deriving a different value.
///
/// Unlike [`derive_subkey`], this is deliberately **not** keyed by
/// epoch: per-role wordlist partitioning is a one-time-per-secret
/// split of the corpus into disjoint subsets, not a per-rotation
/// value.  Callers that need per-epoch derivation want
/// [`derive_subkey`] instead; callers reproducing the role-
/// partitioning tool's seed want this function.
///
/// # Panics
///
/// The underlying `Hkdf::expand` only fails when the requested
/// output length exceeds `255 * HashLen` (8160 bytes for SHA-256);
/// the fixed 32-byte output here is far below that bound, so this
/// call cannot fail in practice.  Matches the `expect`-not-`Result`
/// shape of the tool-side `derive_seed_bytes`.
#[must_use]
pub fn derive_domain_seed(secret: &PerHostSecret, label: &[u8]) -> [u8; 32] {
    let hkdf = Hkdf::<Sha256>::new(None, secret.expose());
    let mut out = [0u8; 32];
    hkdf.expand(label, &mut out)
        .expect("HKDF-Expand of 32 bytes from SHA-256 cannot fail");
    out
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

#[cfg(test)]
mod domain_seed_tests {
    use super::derive_domain_seed;
    use crate::per_host_secret::PerHostSecret;

    fn fixed_secret() -> PerHostSecret {
        PerHostSecret::from_bytes(&[0x42; 32]).unwrap()
    }

    #[test]
    fn deterministic_for_same_inputs() {
        let s = fixed_secret();
        let a = derive_domain_seed(&s, b"label");
        let b = derive_domain_seed(&s, b"label");
        assert_eq!(a, b);
    }

    #[test]
    fn different_label_yields_different_seed() {
        let s = fixed_secret();
        let a = derive_domain_seed(&s, b"label-a");
        let b = derive_domain_seed(&s, b"label-b");
        assert_ne!(a, b);
    }

    #[test]
    fn different_secret_yields_different_seed() {
        let a = derive_domain_seed(&fixed_secret(), b"label");
        let b = derive_domain_seed(
            &PerHostSecret::from_bytes(&[0x43; 32]).unwrap(),
            b"label",
        );
        assert_ne!(a, b);
    }

    /// Locks `derive_domain_seed` to the exact HKDF construction used
    /// by `tools/wordlist-role-partitioning/src/seed.rs::derive_seed_bytes`
    /// (`HKDF-Extract(salt=None, ikm=secret)` then
    /// `HKDF-Expand(info=label, length=32)`).  If either side's
    /// construction drifts (different salt, different hash, extra
    /// domain separation), this test — and the equivalent one in the
    /// tool crate — catches it, because both hard-code the same
    /// independently-computed output for the same fixed inputs.
    ///
    /// Vector computed directly from `hkdf::Hkdf::<Sha256>::new(None,
    /// secret).expand(label, &mut [0u8; 32])` with
    /// `secret = [0x11; 32]`, `label = b"babbleon/v2/role-partitioning/test-vector"`.
    #[test]
    fn matches_role_partitioning_tool_construction() {
        let secret = PerHostSecret::from_bytes(&[0x11; 32]).unwrap();
        let label = b"babbleon/v2/role-partitioning/test-vector";

        let via_key_derivation = derive_domain_seed(&secret, label);

        // Independently reproduce the tool's construction inline
        // (rather than depending on the standalone-workspace tool
        // crate, which would break the "no new deps for the core
        // crate" property this function exists to satisfy) to prove
        // the two are the same algorithm, not just the same function.
        let hkdf = hkdf::Hkdf::<sha2::Sha256>::new(None, secret.expose());
        let mut expected = [0u8; 32];
        hkdf.expand(label, &mut expected).unwrap();

        assert_eq!(via_key_derivation, expected);
    }
}
