//! HKDF-SHA-256 key derivation (RFC 5869).
//!
//! Replaces the prior hand-rolled `SHA-256(host_secret || purpose)` and
//! `HMAC-SHA-256(host_secret, purpose || epoch)` paths.  Functionally
//! equivalent strength on the inputs we use (32-byte uniformly random
//! host secret); the win is *auditor-recognizable shape*: an explicit
//! salt, info, and length triple instead of a custom concatenation.
//!
//! Centralizing here also gives every subkey derivation a single domain-
//! separation surface — change the salt constant to invalidate every
//! derived key at once.  Don't.

use hkdf::Hkdf;
use sha2::Sha256;

/// Domain-separation salt for all Babbleon HKDF derivations.
///
/// HKDF's salt argument is public, not secret — it exists so that two
/// systems using the same `ikm` cannot collide.  Bumping `v1` invalidates
/// every cached mapping table and every previously-derived subkey.
pub const HKDF_SALT: &[u8] = b"babbleon-hkdf-v1";

/// Derive a 32-byte subkey from `ikm` for a specific `info` label.
///
/// `info` is the domain-separation tag for the derivation: every distinct
/// purpose passes a distinct, fixed byte string.  Recipes used in this
/// crate are documented at the call sites.
pub fn derive_subkey_32(ikm: &[u8], info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), ikm);
    let mut out = [0u8; 32];
    hk.expand(info, &mut out)
        .expect("HKDF expand to 32 bytes is always within the 8160-byte limit");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic() {
        let a = derive_subkey_32(b"the-secret", b"purpose-A");
        let b = derive_subkey_32(b"the-secret", b"purpose-A");
        assert_eq!(a, b);
    }

    #[test]
    fn distinct_info_distinct_output() {
        let a = derive_subkey_32(b"the-secret", b"purpose-A");
        let b = derive_subkey_32(b"the-secret", b"purpose-B");
        assert_ne!(a, b, "different info must yield distinct subkeys");
    }

    #[test]
    fn distinct_ikm_distinct_output() {
        let a = derive_subkey_32(b"secret-1", b"purpose");
        let b = derive_subkey_32(b"secret-2", b"purpose");
        assert_ne!(a, b, "different ikm must yield distinct subkeys");
    }

    #[test]
    fn full_entropy_smoke() {
        // A 32-byte HKDF output should not be all zeros for any realistic
        // input.  Cheap sanity check that we are not accidentally returning
        // an unused buffer.
        let out = derive_subkey_32(b"x", b"y");
        assert!(out.iter().any(|&b| b != 0));
    }
}
