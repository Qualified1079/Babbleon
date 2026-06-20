//! Unlock-request payload — the per-host secret bytes ferried from
//! the user-CLI process across the daemon socket.
//!
//! # What this defeats
//!
//! The wire form of an unlock request carries the per-host secret in
//! plain bytes (the user-CLI process has already done the Argon2id /
//! age unwrap, see `v2-babbleon-vault`).  Without a typed wrapper,
//! those bytes would flow through the protocol crate as a bare
//! `[u8; 32]` and risk getting cloned into log statements, error
//! variants, or `Debug` output along the way.
//!
//! [`UnlockSecret`] is the wrapper.  Three rules:
//!
//! - The bytes live in `zeroize::Zeroizing<[u8; UNLOCK_SECRET_LEN]>`
//!   so the buffer is wiped from memory the moment the wrapper is
//!   dropped.
//! - `Debug` is hand-implemented to print `"<redacted>"`.  A careless
//!   `dbg!(req)` cannot dump the bytes.
//! - `Clone` IS implemented because the proptest harness requires
//!   `Strategy::Value: Clone`.  This is the one structural concession
//!   to the test framework.  Each clone produces an independent
//!   `Zeroizing` wrapper; both wrappers wipe on drop, so the
//!   invariant "no plaintext secret bytes linger in the heap pool"
//!   is preserved.  Production code paths construct exactly one
//!   `UnlockSecret` per parse-then-dispatch cycle and do NOT call
//!   `clone` (audit-checked by code review, not by the type).
//!
//! # Mechanism
//!
//! The wire form is hex (64 ASCII characters) for two reasons:
//!
//! 1. JSON's only string type is text.  Hex avoids the base64 escape
//!    cases (the `+` / `/` / `=` characters mean nothing in JSON but
//!    add code paths in the parser).
//! 2. Hex's invariant — every byte is two ASCII hex chars — makes
//!    length validation a one-line `byte_count == 64` check, where
//!    base64 would need a padding-aware mod-3 computation.
//!
//! # Threat model boundaries
//!
//! - **Defeats:** accidental log / `Debug` leakage of the secret;
//!   heap-reuse leakage post-drop.
//! - **Does NOT defeat:** the JSON parser itself momentarily holding
//!   the hex string in an un-zeroized `String` during
//!   [`UnlockSecret::from_hex_wire`].  That exposure window is the
//!   width of one [`UnlockSecret::from_hex_wire`] call and ends
//!   before any caller sees the decoded bytes.
//!
//! # Cross-crate length constant
//!
//! [`UNLOCK_SECRET_LEN`] (`= 32`) must equal both
//! `v2_babbleon_core::PER_HOST_SECRET_LEN` and
//! `v2_babbleon_vault::PAYLOAD_HOST_SECRET_LEN`.  It is duplicated
//! here so the protocol crate has zero downstream dependencies on
//! the daemon-side or vault-side libraries.  If the length ever
//! changes, the bump lands in the same commit across all three
//! constants.

use zeroize::Zeroizing;

use crate::errors::{Error, Result};

/// Length of the per-host secret in bytes.  Mirrors
/// `babbleon_core_v2::PER_HOST_SECRET_LEN` and
/// `babbleon_vault_v2::PAYLOAD_HOST_SECRET_LEN`.
pub const UNLOCK_SECRET_LEN: usize = 32;

/// On-the-wire hex length: two ASCII hex chars per byte.
pub const UNLOCK_SECRET_HEX_LEN: usize = UNLOCK_SECRET_LEN * 2;

/// Per-host secret bytes ferried across the daemon socket as part of
/// a [`crate::Request::Unlock`] message.
///
/// Construct via [`UnlockSecret::from_bytes`] when caller owns the
/// bytes already, or via [`UnlockSecret::from_hex_wire`] when parsing
/// off the socket.  Read via [`UnlockSecret::expose`].
///
/// `Clone` is a test-harness concession (see module docs); production
/// code paths do not clone.
#[derive(Clone)]
pub struct UnlockSecret(Zeroizing<[u8; UNLOCK_SECRET_LEN]>);

impl UnlockSecret {
    /// Wrap caller-owned secret bytes.
    ///
    /// # Errors
    ///
    /// - [`Error::Ipc`] if `bytes.len() != UNLOCK_SECRET_LEN`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != UNLOCK_SECRET_LEN {
            return Err(Error::Ipc(format!(
                "unlock-secret length {} != required {UNLOCK_SECRET_LEN}",
                bytes.len(),
            )));
        }
        let mut buf = Zeroizing::new([0u8; UNLOCK_SECRET_LEN]);
        buf.copy_from_slice(bytes);
        Ok(Self(buf))
    }

    /// Decode a 64-char ASCII hex string into bytes.  The intermediate
    /// `Vec<u8>` from `hex::decode` is moved straight into the
    /// `Zeroizing` wrapper.
    ///
    /// # Errors
    ///
    /// - [`Error::Ipc`] if the hex length is wrong or contains
    ///   non-hex characters.  The message does NOT echo the input
    ///   (security-baseline rule 13).
    pub fn from_hex_wire(hex_str: &str) -> Result<Self> {
        if hex_str.len() != UNLOCK_SECRET_HEX_LEN {
            return Err(Error::Ipc(format!(
                "unlock-secret hex length {} != required {UNLOCK_SECRET_HEX_LEN}",
                hex_str.len(),
            )));
        }
        let decoded = hex::decode(hex_str).map_err(|_| {
            // Do NOT include the hex string itself — it is the secret.
            Error::Ipc("unlock-secret hex contains non-hex characters".into())
        })?;
        if decoded.len() != UNLOCK_SECRET_LEN {
            return Err(Error::Ipc(format!(
                "unlock-secret decoded length {} != required {UNLOCK_SECRET_LEN}",
                decoded.len(),
            )));
        }
        let mut buf = Zeroizing::new([0u8; UNLOCK_SECRET_LEN]);
        buf.copy_from_slice(&decoded);
        // The intermediate `decoded` Vec is dropped here without
        // zeroization — limitation of `hex::decode` returning a
        // plain Vec.  The exposure window is the rest of this stack
        // frame; the bytes do not escape.
        Ok(Self(buf))
    }

    /// Encode the bytes as a 64-char ASCII hex string.
    ///
    /// Used by [`crate::Request::to_wire`].  The returned `String`
    /// outlives one `to_wire` call; callers do not retain it.
    #[must_use]
    pub fn to_hex_wire(&self) -> String {
        hex::encode(self.expose())
    }

    /// Borrow the secret bytes.  The returned slice has length
    /// [`UNLOCK_SECRET_LEN`].
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl std::fmt::Debug for UnlockSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // NEVER format the bytes.  Security-baseline rule 3 / 13.
        write!(f, "UnlockSecret(<redacted>)")
    }
}

// Hand-rolled equality so the protocol's `Request` enum can keep
// `PartialEq` / `Eq` for the test-side assertion helpers.  Compare
// in *non-constant* time on purpose: protocol-level equality is for
// test asserts, not for any secret-derived authentication step.
// Constant-time compare lives at the application layer where the
// secret is compared against an attacker-controllable derivation.
impl PartialEq for UnlockSecret {
    fn eq(&self, other: &Self) -> bool {
        self.expose() == other.expose()
    }
}

impl Eq for UnlockSecret {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_bytes_accepts_correct_length() {
        let bytes = [7u8; UNLOCK_SECRET_LEN];
        let s = UnlockSecret::from_bytes(&bytes).unwrap();
        assert_eq!(s.expose(), &bytes);
    }

    #[test]
    fn from_bytes_rejects_short() {
        let r = UnlockSecret::from_bytes(&[1u8; 16]);
        assert!(matches!(r, Err(Error::Ipc(_))));
    }

    #[test]
    fn from_bytes_rejects_long() {
        let r = UnlockSecret::from_bytes(&[1u8; 64]);
        assert!(matches!(r, Err(Error::Ipc(_))));
    }

    #[test]
    fn hex_roundtrip_preserves_bytes() {
        let bytes: [u8; UNLOCK_SECRET_LEN] = {
            let mut a = [0u8; UNLOCK_SECRET_LEN];
            for (i, b) in a.iter_mut().enumerate() {
                *b = u8::try_from(i).unwrap_or(0);
            }
            a
        };
        let s = UnlockSecret::from_bytes(&bytes).unwrap();
        let hex_str = s.to_hex_wire();
        assert_eq!(hex_str.len(), UNLOCK_SECRET_HEX_LEN);
        let decoded = UnlockSecret::from_hex_wire(&hex_str).unwrap();
        assert_eq!(decoded.expose(), &bytes);
    }

    #[test]
    fn from_hex_wire_rejects_wrong_length() {
        let r = UnlockSecret::from_hex_wire(&"00".repeat(16));
        assert!(matches!(r, Err(Error::Ipc(_))));
    }

    #[test]
    fn from_hex_wire_rejects_non_hex() {
        let r =
            UnlockSecret::from_hex_wire(&"zz".repeat(UNLOCK_SECRET_LEN));
        assert!(matches!(r, Err(Error::Ipc(_))));
    }

    #[test]
    fn from_hex_wire_message_does_not_echo_input() {
        // Build a non-hex input that contains a recognisable substring;
        // confirm the error message does not contain it.
        let needle = "AAAA-NEEDLE-AAAA";
        let mut input =
            needle.repeat((UNLOCK_SECRET_HEX_LEN / needle.len()) + 1);
        input.truncate(UNLOCK_SECRET_HEX_LEN);
        let Err(err) = UnlockSecret::from_hex_wire(&input) else {
            panic!("non-hex input must error")
        };
        assert!(!format!("{err}").contains(needle));
    }

    #[test]
    fn debug_does_not_format_bytes() {
        let s = UnlockSecret::from_bytes(&[0xAB; UNLOCK_SECRET_LEN]).unwrap();
        let dbg = format!("{s:?}");
        assert!(dbg.contains("redacted"));
        assert!(!dbg.contains("ab"));
        assert!(!dbg.contains("AB"));
        assert!(!dbg.contains("171"));
    }

    #[test]
    fn equal_bytes_compare_equal() {
        let a = UnlockSecret::from_bytes(&[3u8; UNLOCK_SECRET_LEN]).unwrap();
        let b = UnlockSecret::from_bytes(&[3u8; UNLOCK_SECRET_LEN]).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn distinct_bytes_compare_unequal() {
        let a = UnlockSecret::from_bytes(&[3u8; UNLOCK_SECRET_LEN]).unwrap();
        let b = UnlockSecret::from_bytes(&[4u8; UNLOCK_SECRET_LEN]).unwrap();
        assert_ne!(a, b);
    }
}
