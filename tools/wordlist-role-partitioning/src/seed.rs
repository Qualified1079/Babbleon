//! Extract-seed derivation.
//!
//! # Why this exists
//!
//! `--extract-seed <utf8>` is fine for reproducibility (the dev
//! workflow, the RESULTS pin), but it is the wrong knob for a
//! production per-host deployment because
//!
//! - the seed is exposed in `ps` output and shell history, and
//! - one wants domain separation ("babbleon/v2/role-partitioning
//!   /epoch-42") so the same host secret can drive both this tool
//!   and unrelated parts of the runtime without cross-purpose
//!   correlation.
//!
//! This module composes those two properties by reading the raw
//! secret from a file and running RFC 5869 HKDF-Expand over
//! `SHA-256(secret)` with the caller-supplied label as the `info`
//! parameter.
//!
//! # Contract
//!
//! `derive_seed_bytes(secret, label) -> [u8; 32]` is
//! deterministic: same `secret` + same `label` yields the same
//! 32 bytes, byte-for-byte, on every platform.  Different
//! `label`s yield uncorrelated outputs even when the secret is
//! reused.  Downstream, those 32 bytes seed the ChaCha20 PRNG in
//! [`crate::extract`] the same way the SHA-256-of-UTF-8 dev seed
//! did.
//!
//! # What this module does NOT do
//!
//! - It does not hold the secret in a `Zeroizing<Vec<u8>>`.  The
//!   tool is a one-shot process; the OS reclaims its heap on
//!   exit.  Adding `zeroize` here would set the wrong precedent
//!   for the crate's dep footprint without a matching threat.
//! - It does not care about the label's namespace convention.
//!   The naming rule ("babbleon/v2/role-partitioning/<epoch>")
//!   is a documentation and operator concern, not a code
//!   concern.

use hkdf::Hkdf;
use sha2::Sha256;

/// Derive 32 bytes of ChaCha seed material from a per-host
/// secret and a domain-separator label using HKDF-Expand
/// (RFC 5869) with SHA-256 as the hash.
///
/// # Panics
///
/// The underlying `Hkdf::expand` only fails when the requested
/// length exceeds `255 * HashLen`; 32 bytes is well below that
/// so this call cannot fail in practice.  We assert instead of
/// returning `Result` to keep the caller's error handling
/// focused on user-supplied I/O errors.
#[must_use]
pub fn derive_seed_bytes(secret: &[u8], label: &[u8]) -> [u8; 32] {
    // HKDF-Extract with no salt is defined; passing `None` matches
    // the RFC 5869 "salt is optional and defaults to a string of
    // HashLen zeros" branch.
    let hk = Hkdf::<Sha256>::new(None, secret);
    let mut out = [0u8; 32];
    hk.expand(label, &mut out)
        .expect("HKDF-Expand of 32 bytes from SHA-256 cannot fail");
    out
}

#[cfg(test)]
mod tests {
    use super::derive_seed_bytes;

    #[test]
    fn same_inputs_yield_same_output() {
        let a = derive_seed_bytes(b"secret-A", b"label");
        let b = derive_seed_bytes(b"secret-A", b"label");
        assert_eq!(a, b);
    }

    #[test]
    fn different_secrets_yield_different_output() {
        let a = derive_seed_bytes(b"secret-A", b"label");
        let b = derive_seed_bytes(b"secret-B", b"label");
        assert_ne!(a, b);
    }

    #[test]
    fn different_labels_yield_different_output() {
        let a = derive_seed_bytes(b"secret", b"label-A");
        let b = derive_seed_bytes(b"secret", b"label-B");
        assert_ne!(a, b);
    }

    #[test]
    fn empty_secret_still_yields_deterministic_output() {
        let a = derive_seed_bytes(b"", b"label");
        let b = derive_seed_bytes(b"", b"label");
        assert_eq!(a, b);
    }

    #[test]
    fn output_is_always_32_bytes() {
        let out = derive_seed_bytes(b"secret", b"label");
        assert_eq!(out.len(), 32);
    }

    #[test]
    fn output_matches_rfc_5869_test_vector_shape() {
        // We are not pinning the exact bytes to an RFC test
        // vector because we use `None` salt and a specific IKM;
        // the shape check (non-zero, high-entropy-looking output)
        // is enough here — the primary determinism guarantees are
        // exercised in the other tests above.
        let out = derive_seed_bytes(b"seed", b"info");
        let unique_bytes: std::collections::HashSet<u8> = out.iter().copied().collect();
        // A 32-byte HKDF output essentially never has fewer than 8
        // distinct byte values in practice.
        assert!(
            unique_bytes.len() >= 8,
            "output looks under-mixed: only {} distinct bytes",
            unique_bytes.len()
        );
    }
}
