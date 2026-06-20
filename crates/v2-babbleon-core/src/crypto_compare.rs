//! Constant-time byte comparison helpers.
//!
//! # What this defeats
//!
//! Variable-time `==` between two byte slices leaks the length of
//! the matching prefix between them.  Repeated against an
//! attacker-controlled input, this leak recovers a secret one byte
//! at a time — the textbook MAC-tag forgery primitive.
//!
//! Every secret-derived compare in v2 — HMAC tags, key bytes,
//! signature payloads, audit-chain hashes — goes through this
//! module.  v2's `#![forbid(unsafe_code)]` policy means we lean on
//! `subtle`'s `Choice` abstraction rather than inline `volatile`
//! tricks.
//!
//! # What this does NOT defeat
//!
//! Timing channels OUTSIDE the byte compare itself.  If the caller
//! short-circuits on the result before writing to a sink, the
//! short-circuit reintroduces a timing channel.  Convention: use
//! `is_secret_byte_match`, convert its boolean output via the
//! pattern below, and gate the response on the boolean without
//! introducing data-dependent branches before the response:
//!
//! ```
//! # use babbleon_core_v2::crypto_compare::is_secret_byte_match;
//! # fn act_on_match() {}
//! # fn act_on_mismatch() {}
//! # let a = &[0u8; 4]; let b = &[0u8; 4];
//! let matches = is_secret_byte_match(a, b);
//! if matches {
//!     act_on_match();
//! } else {
//!     act_on_mismatch();
//! }
//! ```

use subtle::ConstantTimeEq;

/// True iff `a` and `b` are byte-equal, in time independent of the
/// content of either.
///
/// Length differences are observable (the function returns `false`
/// immediately), because the length itself is not a secret in any
/// v2 use case (HMAC tags, signature bytes, and chain hashes are
/// fixed-size by construction).
#[must_use]
pub fn is_secret_byte_match(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

/// True iff two hex strings decode to byte-equal sequences, with
/// the byte compare in constant time relative to the decoded bytes.
///
/// Returns `false` if either input fails to decode.  Length and
/// hex-validity differences are observable in the decode step
/// (they're not secret) but the actual byte content comparison is
/// constant time.
#[must_use]
pub fn is_secret_hex_match(a_hex: &str, b_hex: &str) -> bool {
    let Ok(a) = hex::decode(a_hex) else {
        return false;
    };
    let Ok(b) = hex::decode(b_hex) else {
        return false;
    };
    is_secret_byte_match(&a, &b)
}

#[cfg(test)]
mod tests {
    use super::{is_secret_byte_match, is_secret_hex_match};

    #[test]
    fn equal_bytes_compare_true() {
        assert!(is_secret_byte_match(b"abcd", b"abcd"));
    }

    #[test]
    fn different_bytes_compare_false() {
        assert!(!is_secret_byte_match(b"abcd", b"abce"));
    }

    #[test]
    fn different_lengths_compare_false() {
        assert!(!is_secret_byte_match(b"abc", b"abcd"));
        assert!(!is_secret_byte_match(b"", b"a"));
    }

    #[test]
    fn equal_hex_compares_true() {
        assert!(is_secret_hex_match("deadbeef", "deadbeef"));
    }

    #[test]
    fn equal_hex_is_case_insensitive() {
        assert!(is_secret_hex_match("DEADBEEF", "deadbeef"));
    }

    #[test]
    fn invalid_hex_compares_false() {
        assert!(!is_secret_hex_match("nothex!!", "deadbeef"));
        assert!(!is_secret_hex_match("deadbeef", "nothex!!"));
    }
}
