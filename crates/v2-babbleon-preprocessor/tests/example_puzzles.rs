//! Integration test: round-trip the example puzzles.
//!
//! # What this verifies
//!
//! The five Python puzzles at `tools/scrambler/example-puzzles/`
//! are the operator-confirmed corpus of "realistic small Python
//! files this scrambler must handle".  This test loads each
//! puzzle's source, runs it through tokenize → scramble →
//! unscramble, and asserts the reconstructed source is byte-
//! identical to the original.
//!
//! The test also asserts the scrambled form satisfies the layer-3
//! promise: no visible newline characters.  Internal spaces inside
//! string literals can still appear (they're part of `Word`
//! content, not classified as whitespace tokens), so the
//! no-space assertion is intentionally NOT made.
//!
//! # When this test fails
//!
//! Most likely the MVP tokenizer's limitations were hit by a
//! puzzle that uses something it doesn't support (multi-line
//! string, operator-pasted-to-identifier in a way the
//! unscrambler can't reconstruct).  Check the failing puzzle
//! against `python_tokenizer::MVP_LIMITATIONS` and either:
//!   (a) update the puzzle to fit the MVP subset, or
//!   (b) extend the tokenizer and add a regression test.

use std::path::PathBuf;

use babbleon_core_v2::per_host_secret::PerHostSecret;
use babbleon_core_v2::wordlist::Wordlist;
use babbleon_preprocessor_v2::{
    python_tokenizer::tokenize, scrambler::scramble, unscrambler::unscramble,
    whitespace_wordlist::WhitespaceWordlist,
};

/// All five puzzle filenames, in difficulty order.
const PUZZLES: &[&str] = &[
    "01-fizzbuzz.py",
    "02-running-max.py",
    "03-anagram-groups.py",
    "04-balanced-parens.py",
    "05-merge-intervals.py",
];

fn puzzle_root() -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest_dir).join("../../tools/scrambler/example-puzzles")
}

fn fixed_whitespace_wordlist(epoch: u64) -> WhitespaceWordlist {
    let secret = PerHostSecret::from_bytes(&[0x42; 32]).unwrap();
    WhitespaceWordlist::build(&secret, Wordlist::english_baseline(), epoch)
        .unwrap()
}

/// Helper: assert one puzzle round-trips at the given epoch.
fn assert_round_trip(puzzle_name: &str, epoch: u64) {
    let path = puzzle_root().join(puzzle_name);
    let source = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {puzzle_name}: {e}"));
    let wl = fixed_whitespace_wordlist(epoch);
    let tokens = tokenize(&source);
    let scrambled = scramble(&tokens, &wl).unwrap_or_else(|e| {
        panic!("scramble {puzzle_name} @epoch {epoch}: {e}")
    });
    let reconstructed = unscramble(&scrambled, &wl).unwrap_or_else(|e| {
        panic!("unscramble {puzzle_name} @epoch {epoch}: {e}")
    });
    assert_eq!(
        reconstructed, source,
        "round-trip diverged for {puzzle_name} at epoch {epoch}"
    );
}

#[test]
fn all_puzzles_round_trip_at_epoch_zero() {
    for name in PUZZLES {
        assert_round_trip(name, 0);
    }
}

#[test]
fn all_puzzles_round_trip_at_epoch_one() {
    for name in PUZZLES {
        assert_round_trip(name, 1);
    }
}

#[test]
fn all_puzzles_round_trip_after_many_rotations() {
    // Spot-check epochs across a wider range to surface
    // accidental epoch-zero specifics.
    for &epoch in &[0u64, 1, 7, 99, 100_000, u64::MAX / 2] {
        for name in PUZZLES {
            assert_round_trip(name, epoch);
        }
    }
}

#[test]
fn scrambled_puzzles_contain_no_newline_characters() {
    let wl = fixed_whitespace_wordlist(0);
    for name in PUZZLES {
        let path = puzzle_root().join(name);
        let source = std::fs::read_to_string(&path).unwrap();
        let tokens = tokenize(&source);
        let scrambled = scramble(&tokens, &wl).unwrap();
        assert!(
            !scrambled.contains('\n'),
            "{name}: scrambled output contains '\\n' — layer-3 promise broken"
        );
    }
}

#[test]
fn scrambled_form_is_strictly_larger_than_source() {
    // Sanity: each whitespace marker becomes a 4-word compound
    // averaging ~25 bytes; a single-byte newline expands to ~25
    // bytes; therefore scrambled output should be larger than the
    // input for any non-trivial source.  A test that the input
    // got SMALLER would signal we're dropping content somewhere.
    let wl = fixed_whitespace_wordlist(0);
    for name in PUZZLES {
        let path = puzzle_root().join(name);
        let source = std::fs::read_to_string(&path).unwrap();
        let tokens = tokenize(&source);
        let scrambled = scramble(&tokens, &wl).unwrap();
        assert!(
            scrambled.len() > source.len(),
            "{name}: scrambled ({}b) not larger than source ({}b)",
            scrambled.len(),
            source.len()
        );
    }
}

#[test]
fn epoch_change_changes_scrambled_output() {
    // Rotation is the load-bearing property — it must change
    // every visible byte sequence in the scrambled output.
    let wl0 = fixed_whitespace_wordlist(0);
    let wl1 = fixed_whitespace_wordlist(1);
    for name in PUZZLES {
        let path = puzzle_root().join(name);
        let source = std::fs::read_to_string(&path).unwrap();
        let tokens = tokenize(&source);
        let scrambled0 = scramble(&tokens, &wl0).unwrap();
        let scrambled1 = scramble(&tokens, &wl1).unwrap();
        assert_ne!(
            scrambled0, scrambled1,
            "{name}: scramble produced identical output across epochs"
        );
    }
}
