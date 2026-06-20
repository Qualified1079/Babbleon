//! Vault payload — the plaintext-inside-age JSON structure.
//!
//! # What this defeats
//!
//! The vault payload is the schema for what an unsealed vault
//! contains.  Without a strict schema, a tampered or version-skewed
//! payload would feed garbage bytes into [`crate::Vault::unseal`]'s
//! caller — which builds a [`babbleon_core_v2::PerHostSecret`] from
//! those bytes.  A short-by-one secret, or one with attacker-chosen
//! bytes spliced past the structure boundary, would silently corrupt
//! every downstream derivation.
//!
//! # Mechanism
//!
//! - The schema number ([`PAYLOAD_SCHEMA_CURRENT`]) bumps on every
//!   breaking change to this struct.  Older payloads carry an older
//!   schema number; unseal rejects mismatches.
//! - The secret is held in `Zeroizing<Vec<u8>>` — NOT a `String`,
//!   NOT an owned `Vec<u8>`.  Security-baseline rule 11: the
//!   plaintext secret bytes never live in a non-zeroizing type during
//!   their lifetime in this crate's address space.
//! - Custom (de)serialization for the secret field: serialize as hex
//!   string on the wire, deserialize via a manual `from_value` step
//!   that decodes the hex straight into `Zeroizing<Vec<u8>>`.  The
//!   intermediate `String` lives only inside `serde_json`'s parser
//!   stack frame and is dropped before this module returns; that
//!   exposure window is the best we can do given JSON's text format.
//!
//! # Threat model boundaries
//!
//! - **Defeats:** schema-mismatch silent corruption; long-lived
//!   `String` secret leaks via the serde-derived path.
//! - **Does NOT defeat:** an attacker who modifies the ciphertext.
//!   age provides authenticated encryption (Poly1305 MAC); tampered
//!   ciphertext fails decrypt before this module sees the bytes.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::errors::{Error, Result};

/// Current vault-payload schema version.
///
/// Bump on every breaking change to [`VaultPayload`].  When the
/// number is bumped, [`VaultPayload::from_json_bytes`] must learn to
/// migrate the previous schema OR reject it explicitly with
/// [`Error::Schema`].
pub const PAYLOAD_SCHEMA_CURRENT: u32 = 1;

/// Required length of the host-secret bytes (must match
/// `babbleon_core_v2::PER_HOST_SECRET_LEN`).
///
/// Hardcoded here to keep this crate's dependency graph clean
/// (no edge into the daemon-side core crate).  If
/// `PER_HOST_SECRET_LEN` ever changes, this constant changes in
/// the same commit and the schema number bumps.
pub const PAYLOAD_HOST_SECRET_LEN: usize = 32;

/// The plaintext-inside-age contents of a vault file.
///
/// The host-secret bytes are NOT cloneable: `Zeroizing<Vec<u8>>`
/// itself is `Clone`, but the `VaultPayload` deliberately does not
/// derive `Clone` so callers cannot accidentally proliferate
/// plaintext copies of the secret.
///
/// `Debug` is also intentionally omitted; `Display` is not
/// implemented at all.  The only way to extract the secret is
/// [`VaultPayload::host_secret`], which returns a `&` borrow into
/// the still-owned `Zeroizing` wrapper.
pub struct VaultPayload {
    /// Schema version.  Equals [`PAYLOAD_SCHEMA_CURRENT`] for a
    /// payload built by this crate; smaller values mean an older
    /// vault; larger values mean a forward-incompatible vault.
    schema: u32,

    /// The per-host secret as raw bytes.  Length is
    /// [`PAYLOAD_HOST_SECRET_LEN`].  Never serialized as a `String`
    /// to a `serde::Deserialize`-derived field — see security-baseline
    /// rule 11.
    host_secret: Zeroizing<Vec<u8>>,

    /// Current epoch number at the time of the seal.  After unlock,
    /// the daemon may rotate forward; this field is informational
    /// (the daemon resets it to its own counter on unlock).
    epoch: u64,

    /// Backend tier name (informational only).  Lets a future
    /// `babbleon status --vault` print "soft / TPM / FIDO2" without
    /// linking the backend module.
    tier: String,
}

impl VaultPayload {
    /// Construct a fresh payload from already-generated host-secret
    /// bytes.  Used by [`crate::Vault::seal`] to wrap a new
    /// `PerHostSecret` into a sealable struct.
    ///
    /// # Errors
    ///
    /// - [`Error::Input`] if `host_secret.len() !=
    ///   PAYLOAD_HOST_SECRET_LEN`.
    pub fn new(
        host_secret: Zeroizing<Vec<u8>>,
        epoch: u64,
        tier: impl Into<String>,
    ) -> Result<Self> {
        if host_secret.len() != PAYLOAD_HOST_SECRET_LEN {
            return Err(Error::Input(format!(
                "host_secret bytes len {} != required {PAYLOAD_HOST_SECRET_LEN}",
                host_secret.len()
            )));
        }
        Ok(Self {
            schema: PAYLOAD_SCHEMA_CURRENT,
            host_secret,
            epoch,
            tier: tier.into(),
        })
    }

    /// Borrow the per-host secret bytes.  The slice is exactly
    /// [`PAYLOAD_HOST_SECRET_LEN`] long.  Caller does NOT take
    /// ownership; the bytes remain inside the `Zeroizing` wrapper.
    #[must_use]
    pub fn host_secret(&self) -> &[u8] {
        self.host_secret.as_slice()
    }

    /// Current schema version of this payload.
    #[must_use]
    pub fn schema(&self) -> u32 {
        self.schema
    }

    /// Epoch counter recorded at seal time.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Backend-tier marker (informational).
    #[must_use]
    pub fn tier(&self) -> &str {
        &self.tier
    }

    /// Serialize the payload to JSON bytes (the plaintext that goes
    /// into the age cipher).  Uses the wire form
    /// `{"schema":1,"host_secret_hex":"<64 hex>","epoch":N,"tier":"soft"}`.
    ///
    /// # Errors
    ///
    /// - [`Error::Seal`] if `serde_json` fails to serialize the wire
    ///   struct (cannot happen in practice — wire fields are all
    ///   `Copy` primitives and bounded-length strings).
    pub fn to_json_bytes(&self) -> Result<Vec<u8>> {
        let wire = WirePayload {
            schema: self.schema,
            host_secret_hex: hex::encode(self.host_secret.as_slice()),
            epoch: self.epoch,
            tier: self.tier.clone(),
        };
        serde_json::to_vec(&wire)
            .map_err(|e| Error::Seal(format!("payload encode: {e}")))
    }

    /// Parse JSON bytes into a `VaultPayload`.  Schema-version-checked.
    ///
    /// # Errors
    ///
    /// - [`Error::Unseal`] if the bytes are not valid JSON.
    /// - [`Error::Schema`] if the schema field is missing or refers
    ///   to a version this crate does not understand.
    /// - [`Error::Input`] if the decoded host-secret bytes are the
    ///   wrong length, or the hex string fails to decode.
    pub fn from_json_bytes(bytes: &[u8]) -> Result<Self> {
        let wire: WirePayload = serde_json::from_slice(bytes)
            .map_err(|e| Error::Unseal(format!("payload decode: {e}")))?;
        if wire.schema != PAYLOAD_SCHEMA_CURRENT {
            return Err(Error::Schema(format!(
                "unsupported vault schema {} (this build understands {PAYLOAD_SCHEMA_CURRENT})",
                wire.schema,
            )));
        }
        // Decode hex straight into a Zeroizing wrapper.  The
        // intermediate Vec lives one stack frame.
        let bytes = hex::decode(&wire.host_secret_hex).map_err(|_| {
            // Deliberately do NOT include the hex bytes in the
            // error — rule 13.
            Error::Input("host_secret_hex is not valid hex".into())
        })?;
        if bytes.len() != PAYLOAD_HOST_SECRET_LEN {
            return Err(Error::Input(format!(
                "host_secret bytes len {} != required {PAYLOAD_HOST_SECRET_LEN}",
                bytes.len(),
            )));
        }
        let host_secret = Zeroizing::new(bytes);
        Ok(Self {
            schema: wire.schema,
            host_secret,
            epoch: wire.epoch,
            tier: wire.tier,
        })
    }
}

/// Wire-format struct.  This is the type that `serde` derives
/// (de)serialization for; the `host_secret_hex` field is a `String`
/// — long-lived `String` secrets are exactly what
/// security-baseline rule 11 forbids in the **public** API surface.
/// We keep it private to this module and zeroize-decode at the
/// boundary above (`from_json_bytes`).  The wire-struct itself lives
/// only inside this module; no caller of `VaultPayload::*` ever
/// holds it.
#[derive(Serialize, Deserialize)]
struct WirePayload {
    schema: u32,
    host_secret_hex: String,
    epoch: u64,
    tier: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_secret(byte: u8) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(vec![byte; PAYLOAD_HOST_SECRET_LEN])
    }

    #[test]
    fn new_records_fields() {
        let p = VaultPayload::new(fake_secret(7), 42, "soft").unwrap();
        assert_eq!(p.schema(), PAYLOAD_SCHEMA_CURRENT);
        assert_eq!(p.epoch(), 42);
        assert_eq!(p.tier(), "soft");
        assert_eq!(p.host_secret(), &[7u8; PAYLOAD_HOST_SECRET_LEN]);
    }

    #[test]
    fn new_rejects_short_secret() {
        let short = Zeroizing::new(vec![1u8; 16]);
        let r = VaultPayload::new(short, 0, "soft");
        assert!(matches!(r, Err(Error::Input(_))));
    }

    #[test]
    fn new_rejects_long_secret() {
        let long = Zeroizing::new(vec![1u8; 64]);
        let r = VaultPayload::new(long, 0, "soft");
        assert!(matches!(r, Err(Error::Input(_))));
    }

    #[test]
    fn json_round_trip_preserves_fields() {
        let p = VaultPayload::new(fake_secret(0xAB), 7, "soft").unwrap();
        let bytes = p.to_json_bytes().unwrap();
        let q = VaultPayload::from_json_bytes(&bytes).unwrap();
        assert_eq!(p.schema(), q.schema());
        assert_eq!(p.epoch(), q.epoch());
        assert_eq!(p.tier(), q.tier());
        assert_eq!(p.host_secret(), q.host_secret());
    }

    #[test]
    fn from_json_rejects_wrong_schema() {
        let bytes = serde_json::to_vec(&serde_json::json!({
            "schema": 999,
            "host_secret_hex": "00".repeat(PAYLOAD_HOST_SECRET_LEN),
            "epoch": 0,
            "tier": "soft",
        }))
        .unwrap();
        // VaultPayload has no Debug (rule 3); avoid `unwrap_err`.
        match VaultPayload::from_json_bytes(&bytes) {
            Err(Error::Schema(m)) => assert!(m.contains("999")),
            Err(other) => panic!("expected Error::Schema, got {other}"),
            Ok(_) => panic!("expected Err for unknown schema"),
        }
    }

    #[test]
    fn from_json_rejects_invalid_hex() {
        let bytes = serde_json::to_vec(&serde_json::json!({
            "schema": PAYLOAD_SCHEMA_CURRENT,
            "host_secret_hex": "not hex bytes!!!",
            "epoch": 0,
            "tier": "soft",
        }))
        .unwrap();
        let r = VaultPayload::from_json_bytes(&bytes);
        assert!(matches!(r, Err(Error::Input(_))));
    }

    #[test]
    fn from_json_rejects_wrong_length_decoded() {
        let bytes = serde_json::to_vec(&serde_json::json!({
            "schema": PAYLOAD_SCHEMA_CURRENT,
            "host_secret_hex": "00".repeat(16),
            "epoch": 0,
            "tier": "soft",
        }))
        .unwrap();
        let r = VaultPayload::from_json_bytes(&bytes);
        assert!(matches!(r, Err(Error::Input(_))));
    }

    #[test]
    fn from_json_rejects_invalid_json() {
        let r = VaultPayload::from_json_bytes(b"not json");
        assert!(matches!(r, Err(Error::Unseal(_))));
    }

    #[test]
    fn error_display_never_contains_secret_bytes() {
        // Hand-build a wrong-schema payload that ALSO carries our
        // sentinel secret bytes; confirm the error display does NOT
        // surface them.  Rule 13 enforcement test.
        let bytes = serde_json::to_vec(&serde_json::json!({
            "schema": 999,
            "host_secret_hex": "ee".repeat(PAYLOAD_HOST_SECRET_LEN),
            "epoch": 0,
            "tier": "soft",
        }))
        .unwrap();
        let Err(err) = VaultPayload::from_json_bytes(&bytes) else {
            panic!("wrong-schema payload must error");
        };
        let msg = format!("{err}");
        // The full hex of the secret (32 bytes -> 64 hex chars) must
        // not appear; check a long enough run that real English
        // substring coincidence is ruled out.
        let hex_secret = "ee".repeat(PAYLOAD_HOST_SECRET_LEN);
        assert!(!msg.contains(&hex_secret));
        assert!(!msg.contains(&"ee".repeat(8)));
    }

    #[test]
    fn error_display_on_input_error_never_contains_hex_secret() {
        // The Input("not valid hex") path; double-check it does NOT
        // include the (invalid) hex string the caller passed.
        let bytes = serde_json::to_vec(&serde_json::json!({
            "schema": PAYLOAD_SCHEMA_CURRENT,
            "host_secret_hex": "zz".repeat(PAYLOAD_HOST_SECRET_LEN),
            "epoch": 0,
            "tier": "soft",
        }))
        .unwrap();
        let Err(err) = VaultPayload::from_json_bytes(&bytes) else {
            panic!("invalid-hex payload must error");
        };
        let msg = format!("{err}");
        assert!(!msg.contains(&"zz".repeat(8)));
    }
}
