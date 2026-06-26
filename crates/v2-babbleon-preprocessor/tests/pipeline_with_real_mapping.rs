//! Full production-pipeline round-trip with the REAL `MappingBuilder`.
//!
//! The unit tests in `src/pipeline.rs` use synthetic compound
//! generation; `tests/full_round_trip.rs` uses the real
//! `MappingBuilder` but only on the L2+L3+L4+L5 stretch and bypasses
//! the file-format header.  This file closes the gap:
//!
//! - `scramble_pipeline` + `unscramble_pipeline` are the *only*
//!   composition entry points used.
//! - `MappingBuilder::build` is the same code the production daemon
//!   runs to derive per-token alias compounds, so any drift between
//!   the pipeline's `IdentifierMapping::from_tokens_and_aliases`
//!   contract and what `MappingBuilder` produces fails here.
//! - The full file-format header (`babbleon-v2` / `version:1` /
//!   `epoch:N` / `tokens:...` / `---` / body) is exercised on both
//!   directions; the test passes the encoded `ScrambledFile.file`
//!   bytes (not just the body) to the unscramble side.
//!
//! Python execution (`python3 -c <unscrambled>`) is the load-bearing
//! correctness check: the unscrambled source must run identically to
//! the original.

use babbleon_core_v2::{
    per_host_secret::PerHostSecret, wordlist::Wordlist, MappingBuilder,
};
use babbleon_preprocessor_v2::file_format::decode as decode_file;
use babbleon_preprocessor_v2::identifier_scrambler::{
    IdentifierMapping, ALIAS_COUNT,
};
use babbleon_preprocessor_v2::pipeline::{
    scramble_pipeline, unscramble_pipeline,
};
use babbleon_preprocessor_v2::WhitespaceWordlist;

/// Test-fixed per-host secret.  Any 32-byte constant is fine; this
/// value is arbitrary.  Locking it makes the test reproducible across
/// runs.
fn secret() -> PerHostSecret {
    PerHostSecret::from_bytes(&[0xA5u8; 32]).unwrap()
}

/// Build a `WhitespaceWordlist` for `epoch` using the real HKDF +
/// Fisher-Yates code path from `babbleon-core`.
fn build_whitespace_wordlist(epoch: u64) -> WhitespaceWordlist {
    WhitespaceWordlist::build(
        &secret(),
        Wordlist::english_baseline(),
        epoch,
    )
    .unwrap()
}

/// Build an `IdentifierMapping` for `sorted_tokens` at `epoch` using
/// the real `MappingBuilder` from `babbleon-core`.
///
/// Re-creates the daemon's per-alias virtual-epoch derivation: alias
/// `i` of token `t` is the L2 compound at virtual epoch
/// `epoch * ALIAS_COUNT + i`.  This is the EXACT logic
/// `DaemonState::token_mapping` runs in production; we call it here
/// without the daemon's wire transport.
fn build_real_identifier_mapping(
    sorted_tokens: &[String],
    epoch: u64,
) -> babbleon_preprocessor_v2::errors::Result<IdentifierMapping> {
    let s = secret();
    let wl = Wordlist::english_baseline();
    let builder = MappingBuilder::new(&s, &wl);
    let base = epoch.saturating_mul(ALIAS_COUNT as u64);
    // per_alias[alias_idx] -> per-token compound for that alias.
    let mut per_alias: Vec<Vec<String>> = Vec::with_capacity(ALIAS_COUNT);
    for ai in 0..ALIAS_COUNT {
        let virtual_epoch = base + ai as u64;
        let mapping = builder
            .build(sorted_tokens, virtual_epoch)
            .expect("MappingBuilder::build should not fail for the test corpus");
        let compounds: Vec<String> = sorted_tokens
            .iter()
            .map(|t| {
                mapping
                    .scramble(t)
                    .unwrap_or(t.as_str())
                    .to_string()
            })
            .collect();
        per_alias.push(compounds);
    }
    // Transpose per_alias[alias][token] -> aliases[token][alias].
    let mut aliases: Vec<Vec<String>> = sorted_tokens
        .iter()
        .map(|_| Vec::with_capacity(ALIAS_COUNT))
        .collect();
    for one_alias_set in per_alias {
        for (ti, compound) in one_alias_set.into_iter().enumerate() {
            aliases[ti].push(compound);
        }
    }
    IdentifierMapping::from_tokens_and_aliases(
        sorted_tokens.to_vec(),
        epoch,
        aliases,
    )
}

/// Spawn `python3 -c <program>` and return its stdout on success.
fn python_exec(program: &str) -> Option<String> {
    let out = std::process::Command::new("python3")
        .arg("-c")
        .arg(program)
        .output()
        .ok()?;
    if out.status.success() {
        Some(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        eprintln!(
            "python3 failed: stderr = {}",
            String::from_utf8_lossy(&out.stderr)
        );
        None
    }
}

/// Drive scramble + unscramble through the production pipeline
/// modules using the real `MappingBuilder` for L2 compounds.
fn round_trip(epoch: u64, original: &str) -> String {
    let wl = build_whitespace_wordlist(epoch);
    let scrambled = scramble_pipeline(
        original,
        epoch,
        &wl,
        build_real_identifier_mapping,
    )
    .expect("scramble_pipeline must succeed on test corpus");

    // Parse the header on the unscramble side to mirror the
    // production unscramble path's exact entry sequence.
    let decoded = decode_file(&scrambled.file).expect("decode header");
    assert_eq!(decoded.epoch, epoch, "epoch must round-trip via header");
    let mapping = build_real_identifier_mapping(&decoded.sorted_tokens, epoch)
        .expect("rebuild identifier mapping");
    unscramble_pipeline(
        decoded.version,
        decoded.epoch,
        &decoded.body,
        &wl,
        &mapping,
    )
}

#[test]
fn round_trip_simple_function_def_executes_identically() {
    let original =
        "def greet(name):\n    print(f\"hello {name}\")\n\ngreet(\"world\")\n";
    let unscrambled = round_trip(0, original);
    let original_out = python_exec(original).expect("baseline executes");
    let unscrambled_out = python_exec(&unscrambled).unwrap_or_else(|| {
        panic!("unscrambled failed to execute:\n---\n{unscrambled}\n---")
    });
    assert_eq!(original_out, unscrambled_out);
}

#[test]
fn round_trip_branching_executes_identically() {
    let original = "\
def classify(n):
    if n < 0:
        return \"negative\"
    elif n == 0:
        return \"zero\"
    else:
        return \"positive\"

print(classify(-5))
print(classify(0))
print(classify(42))
";
    let unscrambled = round_trip(0, original);
    let original_out = python_exec(original).expect("baseline executes");
    let unscrambled_out = python_exec(&unscrambled).unwrap_or_else(|| {
        panic!("unscrambled failed to execute:\n---\n{unscrambled}\n---")
    });
    assert_eq!(original_out, unscrambled_out);
}

#[test]
fn round_trip_class_with_methods_executes_identically() {
    let original = "\
class Counter:
    def __init__(self):
        self.value = 0
    def increment(self):
        self.value = self.value + 1
        return self.value

c = Counter()
print(c.increment())
print(c.increment())
print(c.increment())
";
    let unscrambled = round_trip(0, original);
    let original_out = python_exec(original).expect("baseline executes");
    let unscrambled_out = python_exec(&unscrambled).unwrap_or_else(|| {
        panic!("unscrambled failed to execute:\n---\n{unscrambled}\n---")
    });
    assert_eq!(original_out, unscrambled_out);
}

#[test]
fn round_trip_loop_and_list_comprehension_executes_identically() {
    let original = "\
def squares(n):
    return [i * i for i in range(n)]

total = 0
for x in squares(10):
    total = total + x
print(total)
";
    let unscrambled = round_trip(0, original);
    let original_out = python_exec(original).expect("baseline executes");
    let unscrambled_out = python_exec(&unscrambled).unwrap_or_else(|| {
        panic!("unscrambled failed to execute:\n---\n{unscrambled}\n---")
    });
    assert_eq!(original_out, unscrambled_out);
}

#[test]
fn scrambled_body_has_l12_noise_present() {
    // L12 injects zero-width characters (U+200B / U+200C / U+200D)
    // into the body bytes.  This test confirms the file-on-disk
    // contains at least one such character so we know L12 actually
    // ran — a regression to the L3-only pipeline would lack any
    // zero-width bytes.
    let wl = build_whitespace_wordlist(0);
    let scrambled = scramble_pipeline(
        "x = 1\n",
        0,
        &wl,
        build_real_identifier_mapping,
    )
    .unwrap();
    let body = &scrambled.file;
    let has_zwsp =
        body.contains('\u{200B}') || body.contains('\u{200C}') || body.contains('\u{200D}');
    assert!(
        has_zwsp,
        "L12 should inject at least one zero-width codepoint into the body; \
         got: {body:?}"
    );
}

#[test]
fn round_trip_is_deterministic_for_fixed_epoch() {
    // Two scramble passes against the same (secret, epoch) must
    // produce byte-identical output.  Determinism is load-bearing
    // for the daemon's pre-build path and for operator
    // reproducibility.
    let original = "def f():\n    return 7\n\nprint(f())\n";
    let wl = build_whitespace_wordlist(0);
    let a = scramble_pipeline(original, 0, &wl, build_real_identifier_mapping)
        .unwrap();
    let b = scramble_pipeline(original, 0, &wl, build_real_identifier_mapping)
        .unwrap();
    assert_eq!(a.file, b.file, "scramble must be deterministic");
    assert_eq!(a.sorted_tokens, b.sorted_tokens);
}

#[test]
fn round_trip_empty_source_is_well_defined() {
    // Edge case: the operator hands the scrambler a zero-byte file
    // (think: `__init__.py` markers, or a deliberately-empty
    // namespace package).  We must not crash; the round-trip must
    // produce a string that python3 accepts (the canonical empty
    // program is the empty string).
    let original = "";
    let wl = build_whitespace_wordlist(0);
    let scrambled = scramble_pipeline(
        original,
        0,
        &wl,
        build_real_identifier_mapping,
    )
    .expect("scramble_pipeline must accept empty input");
    let decoded = decode_file(&scrambled.file).unwrap();
    let mapping =
        build_real_identifier_mapping(&decoded.sorted_tokens, 0).unwrap();
    let unscrambled = unscramble_pipeline(
        decoded.version,
        decoded.epoch,
        &decoded.body,
        &wl,
        &mapping,
    );
    // python3 -c "" succeeds with empty stdout; the round-trip output
    // should produce the same observable behaviour even if the
    // recovered source has trailing whitespace (the canonicalising
    // re-emit can introduce a final newline).
    let original_out = python_exec(original).expect("python3 -c '' executes");
    let unscrambled_out = python_exec(&unscrambled).unwrap_or_else(|| {
        panic!("unscrambled empty source failed to execute: {unscrambled:?}")
    });
    assert_eq!(original_out, unscrambled_out);
}

#[test]
fn round_trip_comments_only_source_executes_as_noop() {
    // Comments-only file: the python tokenizer treats # as a regular
    // identifier byte run (MVP doesn't split on comments).  The
    // round-trip should still reconstruct text that python3 accepts
    // as a no-op program.
    let original = "# this is the only line in the file\n";
    let unscrambled = round_trip(0, original);
    let original_out = python_exec(original).expect("baseline executes");
    let unscrambled_out = python_exec(&unscrambled).unwrap_or_else(|| {
        panic!("comments-only round-trip failed:\n---\n{unscrambled}\n---")
    });
    assert_eq!(original_out, unscrambled_out);
}

#[test]
fn round_trip_unicode_string_literal_preserves_codepoints() {
    // A non-ASCII string literal stresses L12's homoglyph step: the
    // strip is content-based and reverses every known Cyrillic
    // homoglyph back to its Latin form.  If the original source
    // already contained a U+0430 (Cyrillic 'а'), the strip must not
    // corrupt it back to 'a'.
    //
    // This is the documented L12 limitation: any Latin char in the
    // homoglyph set (`a c e i o p x y`) that appeared in the
    // original via its Cyrillic homoglyph cannot survive a round
    // trip.  But characters OUTSIDE the homoglyph set should pass
    // through.  Pick emoji + a non-homoglyph Cyrillic codepoint.
    let original = "msg = \"\u{1F600} and \u{0431}ear\"\nprint(msg)\n";
    let unscrambled = round_trip(0, original);
    let original_out = python_exec(original).expect("baseline executes");
    let unscrambled_out = python_exec(&unscrambled).unwrap_or_else(|| {
        panic!("unicode round-trip failed:\n---\n{unscrambled}\n---")
    });
    assert_eq!(original_out, unscrambled_out);
}

#[test]
fn different_epochs_produce_different_scrambled_outputs() {
    // Per-epoch derivation is the whole point of rotation.  Two
    // epochs against the same secret must produce different bodies.
    let original = "x = 1\n";
    let wl_a = build_whitespace_wordlist(0);
    let wl_b = build_whitespace_wordlist(7);
    let a =
        scramble_pipeline(original, 0, &wl_a, build_real_identifier_mapping)
            .unwrap();
    let b =
        scramble_pipeline(original, 7, &wl_b, build_real_identifier_mapping)
            .unwrap();
    assert_ne!(a.file, b.file, "different epochs must produce different output");
}
