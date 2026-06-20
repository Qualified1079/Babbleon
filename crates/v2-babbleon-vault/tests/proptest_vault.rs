//! Property-based tests for the vault crate.
//!
//! The deterministic unit tests in `src/payload.rs` and `src/vault.rs`
//! cover the documented invariants (round-trip, wrong-passphrase,
//! non-deterministic ciphertext, ...).  This file covers the
//! *adversarial-input* surface that a fuzz harness would otherwise
//! check:
//!
//! 1. **`VaultPayload` JSON round-trip preserves every field byte-
//!    for-byte for arbitrary (secret bytes, epoch, tier) inputs.**
//!    Catches encoder bugs that would mutate fields silently.
//!
//! 2. **`Vault::seal` -> `Vault::unseal` recovers the exact plaintext
//!    secret for arbitrary (secret bytes, epoch, tier, passphrase).**
//!    The soft backend's Argon2id cost makes us tighten case budget
//!    (each iteration spends ~30 ms on the KDF under the Headless
//!    profile, twice — once for seal, once for unseal).
//!
//! 3. **A `seal` -> wrong-passphrase `unseal` always fails.**
//!    Tests every randomly-mismatched (right, wrong) passphrase pair
//!    surfaces `Error::WrongPassphrase`, never accidentally accepts.
//!
//! 4. **JSON parser never panics on arbitrary bytes.**  Soundness
//!    property — `VaultPayload::from_json_bytes(arbitrary_bytes)`
//!    returns `Result` for every input, never aborts.

// Pedantic relaxations:
// - `doc_markdown` complains about identifier-heavy module-doc text
//   that intentionally reads in plain English (`VaultPayload`,
//   `Argon2id`).
#![allow(clippy::doc_markdown)]

use babbleon_vault_v2::{
    Error, SoftBackend, SoftProfile, Vault, VaultPayload,
    PAYLOAD_HOST_SECRET_LEN, SOFT_BACKEND_NAME,
};
use proptest::array::uniform32;
use proptest::collection::vec;
use proptest::prelude::*;
use zeroize::Zeroizing;

// ----- Strategies -----

/// Generate a fresh-random 32-byte secret as Zeroizing<Vec<u8>>.
fn arb_host_secret() -> impl Strategy<Value = [u8; PAYLOAD_HOST_SECRET_LEN]> {
    uniform32(any::<u8>())
}

/// Generate a "tier" string from a small alphabet so the JSON
/// encoder doesn't have to escape every char.  Empty string is
/// allowed; the payload accepts it as an opaque marker.
fn arb_tier() -> impl Strategy<Value = String> {
    "[a-z0-9_-]{0,32}".prop_map(String::from)
}

/// Generate a passphrase from a printable ASCII alphabet.  Empty
/// rejected by `SoftBackend` so we start at length 1.
fn arb_passphrase() -> impl Strategy<Value = String> {
    "[ -~]{1,64}".prop_map(String::from)
}

fn soft_headless() -> SoftBackend {
    SoftBackend::with_profile(SoftProfile::Headless)
}

// ----- Properties -----

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        ..ProptestConfig::default()
    })]

    /// Payload JSON round-trip: every (secret, epoch, tier) triple
    /// survives `to_json_bytes` -> `from_json_bytes` byte-perfect on
    /// the secret bytes and field-perfect on the metadata.
    #[test]
    fn payload_json_round_trips(
        secret_bytes in arb_host_secret(),
        epoch in any::<u64>(),
        tier in arb_tier(),
    ) {
        let secret = Zeroizing::new(secret_bytes.to_vec());
        let original = VaultPayload::new(secret, epoch, tier.clone()).unwrap();
        let bytes = original.to_json_bytes().expect("encode");
        let parsed = VaultPayload::from_json_bytes(&bytes).expect("decode");
        prop_assert_eq!(parsed.host_secret(), &secret_bytes);
        prop_assert_eq!(parsed.epoch(), epoch);
        prop_assert_eq!(parsed.tier(), tier);
    }

    /// Soundness: arbitrary bytes through `VaultPayload::from_json_bytes`
    /// never panic.  Equivalent to a fuzz harness's no-abort invariant.
    #[test]
    fn payload_from_json_bytes_never_panics(
        bytes in vec(any::<u8>(), 0..4096)
    ) {
        let _ = VaultPayload::from_json_bytes(&bytes);
    }
}

proptest! {
    // Cipher-side properties have a TIGHT budget: each case spends
    // one or two Argon2id derivations.  We size the budget for the
    // CI runner's wall-clock — 4 cases × ~2 derivations × ~1.5 s
    // each ≈ 12 s wall per test.  Catches the obvious encoder bugs
    // without paying for fuzz-level coverage.  Fuzz proper for the
    // cipher boundary lands in `fuzz/` once the v2 cargo-fuzz
    // targets are wired.
    //
    // Adjust upward with `PROPTEST_CASES=N cargo test ...` for
    // ad-hoc tightening; the harness honours the env var via
    // proptest's standard mechanism.
    #![proptest_config(ProptestConfig {
        cases: 4,
        ..ProptestConfig::default()
    })]

    /// Seal/unseal round-trip: every (secret, epoch, tier, passphrase)
    /// recovers the plaintext via the soft backend.
    #[test]
    fn vault_seal_unseal_round_trips(
        secret_bytes in arb_host_secret(),
        epoch in any::<u64>(),
        tier in arb_tier(),
        passphrase in arb_passphrase(),
    ) {
        let secret = Zeroizing::new(secret_bytes.to_vec());
        let payload =
            VaultPayload::new(secret, epoch, tier.clone()).unwrap();
        let vault = Vault::new(soft_headless());
        let sealed = vault
            .seal(&payload, Some(passphrase.as_str()))
            .expect("seal");
        let recovered = vault
            .unseal(&sealed, Some(passphrase.as_str()))
            .expect("unseal");
        prop_assert_eq!(recovered.host_secret(), &secret_bytes);
        prop_assert_eq!(recovered.epoch(), epoch);
        prop_assert_eq!(recovered.tier(), tier);
    }

    /// Wrong-passphrase guard: a seal under `right`, unseal under
    /// `wrong` (where wrong != right) MUST surface as
    /// `Error::WrongPassphrase`, never as a successful unseal with
    /// garbage bytes.
    #[test]
    fn wrong_passphrase_always_fails(
        secret_bytes in arb_host_secret(),
        right in arb_passphrase(),
        wrong in arb_passphrase(),
    ) {
        prop_assume!(right != wrong);
        let secret = Zeroizing::new(secret_bytes.to_vec());
        let payload =
            VaultPayload::new(secret, 0, SOFT_BACKEND_NAME).unwrap();
        let vault = Vault::new(soft_headless());
        let sealed = vault.seal(&payload, Some(right.as_str())).expect("seal");
        match vault.unseal(&sealed, Some(wrong.as_str())) {
            Err(Error::WrongPassphrase) => {}
            Err(other) => prop_assert!(
                false,
                "expected WrongPassphrase, got {other}",
            ),
            Ok(_) => prop_assert!(
                false,
                "wrong passphrase must NOT decrypt successfully",
            ),
        }
    }
}
