//! Property-based tests for the wire protocol.
//!
//! The deterministic unit tests in `src/protocol.rs` cover the
//! documented schema (every variant roundtrips; every documented
//! reject case rejects).  This file covers the *adversarial* surface:
//!
//! 1. **No-panic invariant**: `Request::parse` / `Response::parse`
//!    must return `Result` for every input byte sequence, never
//!    abort.  This is the property a fuzz harness checks; proptest
//!    is the stable-toolchain proxy for that until `cargo fuzz`
//!    targets land for the v2 crates (the existing `fuzz/` dir
//!    targets v1 only).
//!
//! 2. **Roundtrip property**: for every value of every variant,
//!    `parse(value.to_wire()) == Ok(value)`.  Covers arbitrary u64s
//!    (epoch / tracked_count / new_epoch / unix-secs) and arbitrary
//!    JSONL payloads (which must survive the `to_wire`/`parse` boundary
//!    byte-for-byte because the activated-table is opaque to this layer).
//!
//! 3. **Size-cap invariant**: any input longer than
//!    `MAX_REQUEST_BYTES` is rejected by `Request::parse` without
//!    consuming memory proportional to the input.

// Pedantic relaxations for this test harness:
// - `naive_bytecount` would pull in the `bytecount` crate to count
//   newlines in a 100-byte buffer once per test case.  Not worth the
//   dep.
// - `doc_markdown` complains about identifiers in the module doc
//   that intentionally read in plain English (`new_epoch`,
//   `tracked_count`).
#![allow(clippy::naive_bytecount, clippy::doc_markdown)]

use babbleon_daemon_protocol_v2::{
    protocol::WHITESPACE_COMPOUND_COUNT_WIRE,
    ErrorKind, Request, Response, UnlockSecret, ALIAS_COUNT_WIRE,
    MAX_REQUEST_BYTES, MAX_TOKEN_MAPPING_COUNT, UNLOCK_SECRET_LEN,
};
use proptest::array::uniform32;
use proptest::collection::vec;
use proptest::option;
use proptest::prelude::*;

// ----- Strategies -----

fn arb_unlock_secret() -> impl Strategy<Value = UnlockSecret> {
    uniform32(any::<u8>()).prop_map(|bytes: [u8; UNLOCK_SECRET_LEN]| {
        UnlockSecret::from_bytes(&bytes).expect("array length matches")
    })
}

fn arb_token_list() -> impl Strategy<Value = Vec<String>> {
    proptest::collection::vec("[a-z_]{1,32}".prop_map(String::from), 0..8)
}

fn arb_request() -> impl Strategy<Value = Request> {
    prop_oneof![
        Just(Request::Status),
        Just(Request::EmitActivatedTable),
        Just(Request::RotateMapping),
        arb_unlock_secret().prop_map(Request::Unlock),
        Just(Request::GetWhitespaceCompounds),
        arb_token_list().prop_map(|tokens| Request::GetTokenMapping { tokens }),
    ]
}

/// One arbitrary compound — at least one byte to satisfy the
/// schema, capped at 32 bytes so the proptest array does not
/// dominate sample time.  Charset is ASCII-lowercase to keep
/// the proptest body realistic (production compounds are
/// lowercase by HKDF derivation through the wordlist), with
/// some `a-z` repeats per draw to surface dedup edge cases.
fn arb_compound() -> impl Strategy<Value = String> {
    "[a-z]{1,32}".prop_map(String::from)
}

/// Five distinct compounds.  The proptest body re-rolls duplicate
/// draws so the consumer-side `from_compounds` distinctness check
/// is exercised on legitimate inputs without spurious rejection.
fn arb_compounds()
-> impl Strategy<Value = [String; WHITESPACE_COMPOUND_COUNT_WIRE]> {
    proptest::collection::vec(arb_compound(), 5..=5).prop_map(|mut v| {
        // Force distinctness by suffixing position bytes.  Cheap
        // and total over the strategy's domain.
        for (i, s) in v.iter_mut().enumerate() {
            let suffix: u8 = b'a' + u8::try_from(i).unwrap();
            s.push(char::from(suffix));
            s.push(char::from(suffix));
        }
        [
            v[0].clone(),
            v[1].clone(),
            v[2].clone(),
            v[3].clone(),
            v[4].clone(),
        ]
    })
}

/// `aliases[token_idx][alias_idx]` matrix for a token-mapping response.
/// Up to 4 tokens, each with exactly ALIAS_COUNT_WIRE aliases.
fn arb_token_mapping_aliases() -> impl Strategy<Value = Vec<Vec<String>>> {
    proptest::collection::vec(
        proptest::collection::vec(arb_compound(), ALIAS_COUNT_WIRE..=ALIAS_COUNT_WIRE),
        0..4,
    )
}

fn arb_error_kind() -> impl Strategy<Value = ErrorKind> {
    prop_oneof![
        Just(ErrorKind::Vault),
        Just(ErrorKind::Mapping),
        Just(ErrorKind::Wrapper),
        Just(ErrorKind::ActivatedTable),
        Just(ErrorKind::Ipc),
        Just(ErrorKind::BadRequest),
        Just(ErrorKind::Internal),
    ]
}

/// Arbitrary JSONL bytes — any well-formed UTF-8 byte sequence is
/// legal as the activated-table payload from this layer's point of
/// view.  We sample from a mix of ASCII and JSON-significant
/// characters (quotes, backslashes, newlines) so the round-trip
/// covers the encoder's escape path as well as the plain path.
fn arb_jsonl() -> impl Strategy<Value = Vec<u8>> {
    // Build a string from a charset that's heavy on JSON-significant
    // bytes, then return its bytes.  `to_wire` for ActivatedTable
    // requires valid UTF-8 (it embeds the bytes as a JSON string);
    // sampling from a UTF-8 string trivially guarantees that.
    "[a-zA-Z0-9 \\\"\\\\\\n\\t{}:,\\[\\]]{0,512}".prop_map(String::into_bytes)
}

fn arb_response() -> impl Strategy<Value = Response> {
    prop_oneof![
        (any::<u64>(), any::<u64>(), any::<bool>(), option::of(any::<u64>())).prop_map(
            |(epoch, tracked_count, vault_locked, last_rotation_unix_secs)| {
                Response::Status {
                    epoch,
                    tracked_count,
                    vault_locked,
                    last_rotation_unix_secs,
                }
            }
        ),
        (any::<u64>(), arb_jsonl()).prop_map(|(epoch, jsonl)| {
            Response::ActivatedTable { epoch, jsonl }
        }),
        any::<u64>().prop_map(|new_epoch| Response::Rotated { new_epoch }),
        any::<u64>().prop_map(|epoch| Response::Unlocked { epoch }),
        (any::<u64>(), arb_compounds()).prop_map(|(epoch, compounds)| {
            Response::WhitespaceCompounds { epoch, compounds }
        }),
        (any::<u64>(), arb_token_mapping_aliases()).prop_map(|(epoch, aliases)| {
            Response::TokenMapping { epoch, aliases }
        }),
        (arb_error_kind(), ".{0,256}").prop_map(|(kind, message)| {
            Response::Error { kind, message }
        }),
    ]
}

// ----- Properties -----

proptest! {
    #![proptest_config(ProptestConfig {
        // 1024 cases is enough to surface most byte-level edge cases
        // without blowing test wall-clock; each parse() is O(line len)
        // and runs in microseconds.
        cases: 1024,
        ..ProptestConfig::default()
    })]

    /// Soundness: `Request::parse` never panics, on any input bytes.
    #[test]
    fn request_parse_never_panics(bytes in vec(any::<u8>(), 0..4096)) {
        let _ = Request::parse(&bytes);
    }

    /// Soundness: `Response::parse` never panics, on any input bytes.
    #[test]
    fn response_parse_never_panics(bytes in vec(any::<u8>(), 0..4096)) {
        let _ = Response::parse(&bytes);
    }

    /// Soundness on oversize input: the size-cap rejection path must
    /// never panic and must return Err.
    #[test]
    fn request_parse_rejects_oversize_without_panic(
        bytes in vec(any::<u8>(), (MAX_REQUEST_BYTES + 1)..(MAX_REQUEST_BYTES + 256))
    ) {
        let r = Request::parse(&bytes);
        prop_assert!(r.is_err(), "oversize input must be rejected");
    }

    /// Roundtrip: every well-formed Request survives parse(to_wire()).
    #[test]
    fn request_roundtrips(req in arb_request()) {
        let wire = req.to_wire();
        let parsed = Request::parse(&wire).expect("roundtrip parse must succeed");
        prop_assert_eq!(parsed, req);
    }

    /// Roundtrip: every well-formed Response survives parse(to_wire()).
    /// Also asserts the wire form is exactly one line (the framing
    /// invariant the socket layer depends on).
    #[test]
    fn response_roundtrips(resp in arb_response()) {
        let wire = resp.to_wire().expect("response serialisation must succeed");
        let newlines = wire.iter().filter(|b| **b == b'\n').count();
        prop_assert_eq!(newlines, 1, "wire form must contain exactly one newline");
        prop_assert_eq!(wire.last(), Some(&b'\n'));
        let parsed = Response::parse(&wire).expect("roundtrip parse must succeed");
        prop_assert_eq!(parsed, resp);
    }

    /// JSONL byte-preservation: the daemon's ActivatedTable bytes
    /// must survive a wire roundtrip exactly.  A consumer feeds the
    /// bytes verbatim into `ActivatedTable::read_jsonl`, so any
    /// silent normalisation here would corrupt the table.
    #[test]
    fn activated_table_jsonl_byte_preserved(
        epoch in any::<u64>(),
        jsonl in arb_jsonl()
    ) {
        let original = Response::ActivatedTable {
            epoch,
            jsonl: jsonl.clone(),
        };
        let wire = original.to_wire().expect("must serialise");
        let parsed = Response::parse(&wire).expect("must parse");
        match parsed {
            Response::ActivatedTable { epoch: e, jsonl: bytes } => {
                prop_assert_eq!(e, epoch);
                prop_assert_eq!(bytes, jsonl);
            }
            other => prop_assert!(
                false,
                "expected ActivatedTable, got {:?}",
                other
            ),
        }
    }
}
