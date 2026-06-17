//! Crypto primitives that aren't tied to a specific module.
//!
//! Currently houses one helper: a constant-time byte-slice equality
//! check.  Centralizing here means every secret-derived comparison can
//! be located by `grep ct_eq` at audit time, and the pattern is set up
//! for the Ed25519 audit-log signing path (where comparison of derived
//! material against attacker-controllable input becomes load-bearing).

use subtle::ConstantTimeEq;

/// Compare two byte slices in constant time relative to their length.
///
/// Use anywhere a comparison's branch behaviour would otherwise leak
/// information about secret-derived bytes — MAC tags, vault key
/// material, FIDO2 authenticator responses, signatures.  For purely
/// public values (hash-chain prevs, file contents the attacker already
/// knows) plain `==` is fine; reach for this when the *result* of the
/// comparison is what an attacker would want to learn.
///
/// Returns `false` for length mismatch without inspecting bytes, which
/// is the standard subtle-style API: the length difference itself is
/// not secret-derived in any of our call sites.
#[inline]
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equal_slices_compare_equal() {
        assert!(ct_eq(b"hello", b"hello"));
        assert!(ct_eq(&[0u8; 32], &[0u8; 32]));
    }

    #[test]
    fn unequal_slices_compare_unequal() {
        assert!(!ct_eq(b"hello", b"world"));
        assert!(!ct_eq(&[1u8; 32], &[2u8; 32]));
    }

    #[test]
    fn length_mismatch_compares_unequal() {
        assert!(!ct_eq(b"short", b"a-longer-input"));
        assert!(!ct_eq(b"", b"x"));
    }

    #[test]
    fn empty_slices_compare_equal() {
        assert!(ct_eq(b"", b""));
    }

    #[test]
    fn one_bit_difference_detected() {
        // Constant time, but still semantically correct: a single
        // differing bit at any position must yield `false`.
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        for byte in 0..32 {
            for bit in 0..8 {
                a[byte] = 0;
                b[byte] = 1u8 << bit;
                assert!(!ct_eq(&a, &b), "differ in byte {byte} bit {bit}");
            }
        }
    }
}
