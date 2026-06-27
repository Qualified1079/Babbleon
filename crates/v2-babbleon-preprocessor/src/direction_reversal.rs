//! Layer 6 — direction segment reversal.
//!
//! # What this defeats
//!
//! After L3 emits a wall of per-epoch wordlist compounds, an attacker
//! with the wordlist can still grep the body for compound boundaries:
//! BPE merges and substring-match heuristics recover the original
//! compound *sequence* even though they cannot resolve identities.
//!
//! L6 byte-reverses pseudorandom chunks of the body so the visual
//! reading order — and the surface signal that a BPE merge follows —
//! is destroyed.  A run like `riverstoneanvilfreckle` becomes
//! `relkcerflivnaenotsrevir` when its chunk is reversed; the
//! attacker's wordlist match fails because the chars are reordered.
//!
//! Composes with L12 (tokenizer noise) — L6 runs first on bytes
//! drawn from the ASCII compound alphabet, then L12 inserts
//! zero-width / homoglyph noise into the reversed wall.  An
//! attacker now has to brute-force chunk boundaries AND strip
//! zero-widths AND undo homoglyph substitutions before any wordlist
//! match has a chance.
//!
//! # Composition
//!
//! Scramble pipeline:
//!
//!   tokenize → L4 → L5 → L2 → L3 → **L6** → L12 → write
//!
//! Unscramble pipeline:
//!
//!   read → L12⁻¹ → **L6⁻¹** → L3⁻¹ → L2⁻¹ → L5⁻¹ → L4⁻¹ → emit
//!
//! # Inverse design
//!
//! [`unreverse_chunks`] is **literally [`reverse_chunks`] called
//! again with the same epoch**.  Two facts make this work:
//!
//! 1. The xorshift PRNG seeded by `(epoch, L6 domain tag)` produces
//!    the same `(chunk_size, reverse_decision)` sequence on both
//!    passes.
//! 2. Reversal is its own inverse.  Reversing a chunk twice — same
//!    boundaries — yields the original chunk.
//!
//! Chunks are sized in *characters*, not bytes, so the reverse is
//! UTF-8-safe.  L6 runs before L12 in the scramble direction so its
//! input is pure ASCII; in the unscramble direction L6 runs AFTER L12
//! strip so its input is again pure ASCII, and the symmetry holds
//! regardless of which side has multi-byte UTF-8.
//!
//! # Threat-model boundary
//!
//! - Defeats: naive wordlist grep, BPE merge prediction over the
//!   ASCII compound alphabet, eyeball reading order.
//! - Does NOT defeat: an attacker who knows the per-epoch PRNG seed
//!   and L6 constants — they reconstruct the chunk pattern and
//!   reverse exactly the same chunks.  Like L12, L6 raises cost on
//!   the naive bytes-into-tokenizer path; protection of the *epoch*
//!   itself comes from the daemon (it never leaves the trusted tier).
//!
//! # MVP scope
//!
//! - Variable chunk size in `[MIN_CHUNK_CHARS, MAX_CHUNK_CHARS]`
//!   sampled uniformly from the per-epoch PRNG.  Variable sizing
//!   defeats a brute-force "try every chunk size 1..N" attack.
//! - Reversal decision per chunk is a fair coin from the same PRNG.
//!   ~50% of chunks reverse.
//! - L6 operates on the L3 body string (chars, not bytes).
//! - Empty / single-char bodies are returned unchanged structurally
//!   (trivial chunk).

/// Inclusive lower bound (in chars) for the per-epoch chunk size.
const MIN_CHUNK_CHARS: usize = 16;

/// Inclusive upper bound (in chars) for the per-epoch chunk size.
const MAX_CHUNK_CHARS: usize = 48;

/// PRNG draw modulus for the reverse decision.  2 ⇒ a fair coin.
/// Bigger numbers reduce the fraction of reversed chunks.
const REVERSE_DENOM: usize = 2;

/// Tiny xorshift64 PRNG with an L6-specific domain tag.
///
/// Carries zero security weight; the security of L6 against an
/// attacker who knows the seed is intentionally zero (the seed is
/// the per-epoch index, which a colluding party already knows).
/// L6's value is forcing the unwary attacker to undo it.
struct XorShift64(u64);

impl XorShift64 {
    fn from_epoch(epoch: u64) -> Self {
        let seed = epoch
            .wrapping_mul(0x7C9F_E1B3_5A4D_F018)
            ^ 0x1B4E_9C72_AD56_F839;
        Self(if seed == 0 { 0xFEED_BABE_C0DE_F00D } else { seed })
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn gen_range(&mut self, exclusive_upper: usize) -> usize {
        // Mod at u64 width before truncating to usize.  A 32-bit `usize`
        // would otherwise drop the upper PRNG bits before the mod, which
        // changes the chunk-size and reverse-decision sequence.  Since L6
        // is involutive (the unscrambler is the same function), any
        // divergence between scrambler and unscrambler architectures
        // would silently corrupt the body.  The final `as usize` is
        // lossless because `modulus` came from a usize.
        let modulus = exclusive_upper.max(1) as u64;
        #[allow(clippy::cast_possible_truncation)] // bounded above by `modulus`
        let bucket = (self.next_u64() % modulus) as usize;
        bucket
    }
}

/// Apply L6: reverse pseudorandom variable-length chunks of `body`
/// according to a per-epoch PRNG.  Returns the chunk-reversed bytes.
///
/// Empty input is returned unchanged.  Bodies shorter than
/// `MIN_CHUNK_CHARS` get a single trivial chunk that the PRNG may or
/// may not flip; correctness is preserved either way because
/// [`unreverse_chunks`] (this same function with the same epoch)
/// applies the symmetric inverse.
#[must_use]
pub fn reverse_chunks(body: &str, epoch: u64) -> String {
    if body.is_empty() {
        return String::new();
    }
    let chars: Vec<char> = body.chars().collect();
    let mut rng = XorShift64::from_epoch(epoch);
    let mut out = String::with_capacity(body.len());
    let mut i = 0usize;
    while i < chars.len() {
        // Sample chunk size and reverse decision in a fixed order so
        // the inverse pass reproduces the same sequence of draws.
        let span = MAX_CHUNK_CHARS - MIN_CHUNK_CHARS + 1;
        let chunk_size = MIN_CHUNK_CHARS + rng.gen_range(span);
        let should_reverse = rng.gen_range(REVERSE_DENOM) == 0;
        let end = (i + chunk_size).min(chars.len());
        if should_reverse {
            for c in chars[i..end].iter().rev() {
                out.push(*c);
            }
        } else {
            for c in &chars[i..end] {
                out.push(*c);
            }
        }
        i = end;
    }
    out
}

/// Apply L6 inverse: undo the per-epoch chunk reversal pattern.
///
/// Mathematically identical to [`reverse_chunks`] because reversal
/// is involutive (`reverse(reverse(s)) == s`) and the PRNG sequence
/// from the same epoch is identical on both passes.  Defined as a
/// distinct symbol so callers express intent at call sites and we
/// can change the inverse independently later if the layer ever
/// becomes asymmetric.
#[must_use]
pub fn unreverse_chunks(body: &str, epoch: u64) -> String {
    reverse_chunks(body, epoch)
}

#[cfg(test)]
mod tests {
    use super::{reverse_chunks, unreverse_chunks, MAX_CHUNK_CHARS, MIN_CHUNK_CHARS};

    #[test]
    fn empty_body_round_trips() {
        assert_eq!(reverse_chunks("", 0), "");
        assert_eq!(unreverse_chunks("", 0), "");
    }

    #[test]
    fn round_trip_holds_for_many_epochs_and_body_lengths() {
        let alphabet: Vec<char> = ('a'..='z').collect();
        for epoch in 0u64..32 {
            for len in [1usize, 2, 15, 16, 17, 47, 48, 49, 100, 256, 1024] {
                let body: String = (0..len)
                    .map(|i| alphabet[(i + epoch as usize) % alphabet.len()])
                    .collect();
                let reversed = reverse_chunks(&body, epoch);
                let undone = unreverse_chunks(&reversed, epoch);
                assert_eq!(
                    undone, body,
                    "round-trip failed at epoch={epoch}, len={len}"
                );
            }
        }
    }

    #[test]
    fn reverse_is_deterministic_per_epoch() {
        let body = "thequickbrownfoxjumpsoverthelazydog".repeat(8);
        let a = reverse_chunks(&body, 42);
        let b = reverse_chunks(&body, 42);
        let c = reverse_chunks(&body, 43);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn reverse_preserves_char_count_and_set() {
        let body = "thequickbrownfoxjumpsoverthelazydog".repeat(4);
        let reversed = reverse_chunks(&body, 7);
        assert_eq!(
            reversed.chars().count(),
            body.chars().count(),
            "char count must be preserved"
        );
        let mut a: Vec<char> = body.chars().collect();
        let mut b: Vec<char> = reversed.chars().collect();
        a.sort_unstable();
        b.sort_unstable();
        assert_eq!(a, b, "char multiset must be preserved");
    }

    #[test]
    fn body_shorter_than_chunk_size_still_round_trips() {
        let body = "abc";
        for epoch in 0u64..16 {
            let reversed = reverse_chunks(body, epoch);
            let undone = unreverse_chunks(&reversed, epoch);
            assert_eq!(undone, body, "round-trip failed at epoch={epoch}");
            assert_eq!(reversed.chars().count(), body.chars().count());
        }
    }

    #[test]
    fn reverse_actually_mutates_a_long_body_in_most_epochs() {
        // For a long body where many chunks have a 50% chance of
        // reversing each, the probability of *zero* chunks reversing
        // is vanishing — assert at least one epoch in 16 produces a
        // body that differs from the original.
        let body = "thequickbrownfoxjumpsoverthelazydog".repeat(8);
        let mut any_differs = false;
        for epoch in 0u64..16 {
            if reverse_chunks(&body, epoch) != body {
                any_differs = true;
                break;
            }
        }
        assert!(
            any_differs,
            "expected some epoch to produce a different body"
        );
    }

    #[test]
    fn round_trip_holds_with_multibyte_utf8_chars() {
        // Strip-then-reverse scenarios may legitimately put multi-byte
        // characters in the L6 input.  Validate the char-based
        // reversal doesn't corrupt them.
        let body = "thequickbrownfoxjumps\u{0435}overthelazydog\u{0430}";
        let reversed = reverse_chunks(body, 11);
        let undone = unreverse_chunks(&reversed, 11);
        assert_eq!(undone, body);
    }

    #[test]
    fn min_max_chunk_constants_are_sane() {
        assert!(MIN_CHUNK_CHARS < MAX_CHUNK_CHARS);
        assert!(MIN_CHUNK_CHARS >= 1);
    }

    #[test]
    fn unreverse_is_an_alias_of_reverse() {
        let body = "abcdefghijklmnop".repeat(10);
        for epoch in [0u64, 7, 42, 1_000_000] {
            assert_eq!(
                reverse_chunks(&body, epoch),
                unreverse_chunks(&body, epoch),
                "the two functions are documented as aliases"
            );
        }
    }

    #[test]
    fn does_not_introduce_newline_or_tab_into_ascii_body() {
        // L3 produces bodies with no \n / \t; L6 must not introduce
        // either (header parsing relies on \n being a header-only
        // delimiter).
        let body = "abcdefghijklmnopqrstuvwxyz".repeat(50);
        for epoch in 0u64..32 {
            let reversed = reverse_chunks(&body, epoch);
            assert!(!reversed.contains('\n'));
            assert!(!reversed.contains('\t'));
        }
    }
}
