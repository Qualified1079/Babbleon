//! Layer 12 — tokenizer-hostile noise.
//!
//! # What this defeats
//!
//! After L3 emits its body, the scrambled file is a wall of ASCII
//! lowercase letters drawn from the per-epoch wordlist.  An LLM
//! tokenizer reading that wall produces a small, predictable bag of
//! BPE tokens — the wordlist compounds are English-shaped, so BPE
//! merges them efficiently.
//!
//! L12 perturbs the body bytes so the same wall, semantically
//! identical to the trusted-tier reader (who strips L12 first), is
//! tokenizer-hostile to the adversary's LLM:
//!
//! 1. **Zero-width injection.**  ZWSP (U+200B), ZWNJ (U+200C), and
//!    ZWJ (U+200D) are inserted at deterministic per-epoch positions.
//!    They take 3 UTF-8 bytes each, are invisible in any reader, and
//!    every mainstream BPE tokenizer (cl100k, o200k, Llama-3, Qwen)
//!    segments them as their own one-token unit — bloating the
//!    attacker's prompt by multi-x in the limit.
//! 2. **Cyrillic homoglyph substitution.**  At deterministic per-epoch
//!    positions, the Latin letters `a c e i o p x y` are swapped for
//!    their Cyrillic homoglyphs (U+0430, U+0441, U+0435, U+0456,
//!    U+043E, U+0440, U+0445, U+0443).  Same visual glyph, two UTF-8
//!    bytes each, breaks every BPE merge that spans the substituted
//!    position.  An LLM that has trained on natural English text sees
//!    a soup of unknown sub-tokens.
//!
//! # Composition
//!
//! L12 runs LAST on scramble (after L3 emits the body), FIRST on
//! unscramble (before L3 takes the body for greedy matching).  It
//! operates on the L3 body bytes only — never on the file header,
//! which holds the (potentially non-ASCII) original token list and
//! must round-trip byte-for-byte.
//!
//! Scramble:  ... → L3 → **L12 inject** → write file.
//! Unscramble: read file → **L12 strip** → L3⁻¹ → ...
//!
//! # Inverse design
//!
//! [`strip_noise`] is **content-based**, not position-based: it
//! removes every zero-width character it sees and replaces every
//! known Cyrillic homoglyph with its ASCII counterpart.  No epoch is
//! needed at strip time.  Idempotent: calling it on a clean body
//! returns the body unchanged.  Robust to partial corruption (a
//! truncated zero-width sequence is safely dropped).
//!
//! This is safe because:
//!
//! - The L3 body is pure ASCII lowercase (compounds drawn from the
//!   English wordlist) before L12 runs.  No ASCII character in `[a-z]`
//!   can be confused with a Cyrillic homoglyph during strip.
//! - Zero-width characters never appear in the L3 wordlist (compounds
//!   are validated ASCII).  Stripping every ZWJ/ZWSP/ZWNJ from the
//!   body restores the original byte stream exactly.
//!
//! # Threat-model boundary
//!
//! - Defeats: LLM-tokenizer-based attackers reading the scrambled
//!   file directly into a model prompt.  Inflates their token count;
//!   degrades BPE locality; introduces non-English signal that derails
//!   pre-trained code completion.
//! - Does NOT defeat: an attacker who runs the same `strip_noise` we
//!   ship in the unscrambler.  L12 raises cost on the naive
//!   bytes-to-LLM-prompt path, nothing else.  No secret protection
//!   compared to L2/L7.
//!
//! # MVP scope
//!
//! - Zero-width injection rate is ~1 character per
//!   [`ZERO_WIDTH_PERIOD`] body characters.
//! - Homoglyph substitution rate is ~1 substitution per
//!   [`HOMOGLYPH_PERIOD`] *eligible* characters (`a c e i o p x y`).
//! - Per-epoch xorshift PRNG drives both jitters; the same epoch
//!   reproduces the same noise layout.  Strip is epoch-free.

use std::collections::HashMap;

/// Average period (in body characters) between zero-width injections.
/// Lower → noisier and larger file; higher → quieter.  4 is the
/// MVP — every fourth character gets a zero-width neighbour on
/// average.
const ZERO_WIDTH_PERIOD: usize = 4;

/// Average period (in *eligible* characters) between homoglyph
/// substitutions.  3 is the MVP — about one in three eligible
/// letters gets swapped, which is dense enough to derail BPE
/// merges without inflating the file beyond ~30%.
const HOMOGLYPH_PERIOD: usize = 3;

/// The three zero-width characters L12 injects.  Cycled in this
/// order by the per-epoch PRNG.
const ZERO_WIDTH_CODEPOINTS: [char; 3] = ['\u{200B}', '\u{200C}', '\u{200D}'];

/// Latin → Cyrillic homoglyph map.  Each Latin character on the
/// left is visually identical to the Cyrillic character on the
/// right under every mainstream font.
///
/// Source: Unicode Confusables List (UTS #39), Cyrillic subset that
/// covers the most common lowercase Latin letters appearing in
/// English wordlists.
const HOMOGLYPHS: [(char, char); 8] = [
    ('a', '\u{0430}'),
    ('c', '\u{0441}'),
    ('e', '\u{0435}'),
    ('i', '\u{0456}'),
    ('o', '\u{043E}'),
    ('p', '\u{0440}'),
    ('x', '\u{0445}'),
    ('y', '\u{0443}'),
];

/// Tiny xorshift64 PRNG with a layer-12-specific domain tag.
///
/// Carries zero security weight — strip is content-based, so the
/// PRNG only governs *where* noise lands, not whether it can be
/// reversed.
struct XorShift64(u64);

impl XorShift64 {
    fn from_epoch(epoch: u64) -> Self {
        let seed = epoch
            .wrapping_mul(0xA5C2_F0E3_7B91_4D67)
            ^ 0x4F1A_E2B7_0C9D_3851;
        Self(if seed == 0 { 0xB16B_00B5_F00D_FACE } else { seed })
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
        // Mod at u64 width.  Truncating the PRNG output to `usize` first
        // would drop the upper 32 bits on 32-bit targets and produce a
        // different noise-insertion sequence than a 64-bit host running
        // the same epoch.  Although L12 strips are content-based and
        // therefore idempotent, the inserted positions still need to be
        // architecture-stable for benchmark and corpus-test reproducibility.
        // The final `as usize` is lossless because `modulus` came from a usize.
        let modulus = exclusive_upper.max(1) as u64;
        #[allow(clippy::cast_possible_truncation)] // bounded above by `modulus`
        let bucket = (self.next_u64() % modulus) as usize;
        bucket
    }
}

/// Inject L12 noise into `body` and return the noisy bytes.
///
/// Two passes:
///
/// 1. Walk the body characters.  Track a per-pass step counter; once
///    it reaches the next pseudorandom threshold within
///    `[1, 2 * ZERO_WIDTH_PERIOD]`, insert one of the three
///    zero-width codepoints (cycled by PRNG) and reset the counter.
/// 2. Walk the (now zero-width-bearing) characters.  For each one
///    in the homoglyph table, with a per-character PRNG draw
///    against `HOMOGLYPH_PERIOD`, substitute the Cyrillic
///    homoglyph.
///
/// The two passes share one [`XorShift64`] so the full noise layout
/// is fully determined by `epoch`.
///
/// Empty input is returned unchanged.
#[must_use]
pub fn inject_noise(body: &str, epoch: u64) -> String {
    if body.is_empty() {
        return String::new();
    }

    let mut rng = XorShift64::from_epoch(epoch);

    // Pass 1: zero-width injection.
    let mut after_zw: Vec<char> = Vec::with_capacity(body.len() * 2);
    let mut next_insert_at = rng.gen_range(2 * ZERO_WIDTH_PERIOD) + 1;
    let mut zw_cycle = 0usize;
    for (idx, ch) in body.chars().enumerate() {
        after_zw.push(ch);
        if idx + 1 >= next_insert_at {
            let zw = ZERO_WIDTH_CODEPOINTS
                [zw_cycle % ZERO_WIDTH_CODEPOINTS.len()];
            after_zw.push(zw);
            zw_cycle = zw_cycle.wrapping_add(1);
            // Reroll the next step ahead of where we currently are.
            next_insert_at = idx + 1 + rng.gen_range(2 * ZERO_WIDTH_PERIOD) + 1;
        }
    }

    // Pass 2: homoglyph substitution.
    let homoglyph_lookup: HashMap<char, char> =
        HOMOGLYPHS.iter().copied().collect();
    let mut out = String::with_capacity(after_zw.len() * 2);
    for ch in after_zw {
        if let Some(&cyrillic) = homoglyph_lookup.get(&ch) {
            // PRNG draw against HOMOGLYPH_PERIOD: ~1/period
            // substitutes; never mutates a zero-width or
            // already-substituted character (those are not in the
            // lookup).
            if rng.gen_range(HOMOGLYPH_PERIOD) == 0 {
                out.push(cyrillic);
                continue;
            }
        }
        out.push(ch);
    }
    out
}

/// Strip every zero-width character and every known Cyrillic
/// homoglyph from `body`, returning the cleaned bytes.
///
/// Content-based — needs no epoch and is idempotent.  Returns the
/// original L3 body byte-for-byte when called on a properly
/// L12-encoded body.  Safe to call on a body that never went
/// through [`inject_noise`].
#[must_use]
pub fn strip_noise(body: &str) -> String {
    if body.is_empty() {
        return String::new();
    }
    let reverse_lookup: HashMap<char, char> =
        HOMOGLYPHS.iter().map(|&(latin, cyr)| (cyr, latin)).collect();
    let mut out = String::with_capacity(body.len());
    for ch in body.chars() {
        if is_zero_width(ch) {
            continue;
        }
        if let Some(&latin) = reverse_lookup.get(&ch) {
            out.push(latin);
        } else {
            out.push(ch);
        }
    }
    out
}

/// True if `ch` is one of the three zero-width codepoints L12 injects.
#[must_use]
pub fn is_zero_width(ch: char) -> bool {
    ZERO_WIDTH_CODEPOINTS.contains(&ch)
}

/// True if `ch` is one of the Cyrillic homoglyphs L12 substitutes.
///
/// Useful for assertions and tests; production code calls
/// [`strip_noise`] directly.
#[must_use]
pub fn is_homoglyph(ch: char) -> bool {
    HOMOGLYPHS.iter().any(|&(_, cyr)| cyr == ch)
}

/// True if `body` contains any L12 noise (zero-width or homoglyph).
///
/// Diagnostic helper.  Not load-bearing for round-trip correctness;
/// `strip_noise` is idempotent on clean input.
#[must_use]
pub fn has_any_noise(body: &str) -> bool {
    body.chars().any(|c| is_zero_width(c) || is_homoglyph(c))
}

#[cfg(test)]
mod tests {
    use super::{
        has_any_noise, inject_noise, is_homoglyph, is_zero_width,
        strip_noise, HOMOGLYPHS, ZERO_WIDTH_CODEPOINTS,
    };

    #[test]
    fn empty_body_round_trips() {
        assert_eq!(inject_noise("", 0), "");
        assert_eq!(strip_noise(""), "");
    }

    #[test]
    fn ascii_body_round_trips_under_l12() {
        let body = "thequickbrownfoxjumpsoverthelazydog";
        for epoch in [0u64, 1, 7, 42, 1_000_000] {
            let noisy = inject_noise(body, epoch);
            let clean = strip_noise(&noisy);
            assert_eq!(clean, body, "round-trip failed at epoch {epoch}");
        }
    }

    #[test]
    fn injection_produces_zero_width_chars() {
        let body = "thequickbrownfoxjumpsoverthelazydog";
        let noisy = inject_noise(body, 7);
        let n_zw = noisy.chars().filter(|c| is_zero_width(*c)).count();
        // body is 35 chars long; ZERO_WIDTH_PERIOD=4 expects
        // roughly 35/4 = 8-9 injections on average (uniform[1, 8]
        // step), but the PRNG-driven variance is wide so accept
        // any non-zero count.
        assert!(n_zw > 0, "expected at least one zero-width char");
    }

    #[test]
    fn injection_produces_homoglyphs_when_eligible_chars_present() {
        let body = "appleorangepearmangocyanyoyo"; // dense in eligible chars
        let noisy = inject_noise(body, 11);
        let n_hg = noisy.chars().filter(|c| is_homoglyph(*c)).count();
        assert!(
            n_hg > 0,
            "body with many eligible chars must produce some \
             homoglyphs at epoch 11; got {n_hg}"
        );
    }

    #[test]
    fn injection_is_deterministic_per_epoch() {
        let body = "thequickbrownfoxjumpsoverthelazydog";
        let a = inject_noise(body, 42);
        let b = inject_noise(body, 42);
        let c = inject_noise(body, 43);
        assert_eq!(a, b, "same epoch must produce same noise");
        assert_ne!(a, c, "different epochs must differ");
    }

    #[test]
    fn strip_noise_is_idempotent_on_clean_body() {
        let body = "abcdefghijklmnopqrstuvwxyz";
        let stripped = strip_noise(body);
        assert_eq!(stripped, body);
        let twice = strip_noise(&stripped);
        assert_eq!(twice, body);
    }

    #[test]
    fn strip_noise_removes_zero_width_chars_alone() {
        let mut body = String::from("hello");
        for zw in ZERO_WIDTH_CODEPOINTS {
            body.push(zw);
        }
        body.push_str("world");
        let cleaned = strip_noise(&body);
        assert_eq!(cleaned, "helloworld");
    }

    #[test]
    fn strip_noise_reverses_homoglyph_substitutions() {
        let mut body = String::new();
        for (_latin, cyr) in HOMOGLYPHS {
            body.push(cyr);
        }
        let cleaned = strip_noise(&body);
        let expected: String = HOMOGLYPHS.iter().map(|&(l, _)| l).collect();
        assert_eq!(cleaned, expected);
    }

    #[test]
    fn has_any_noise_detects_zero_width() {
        let mut body = String::from("clean");
        body.push(ZERO_WIDTH_CODEPOINTS[0]);
        assert!(has_any_noise(&body));
    }

    #[test]
    fn has_any_noise_detects_homoglyph() {
        let mut body = String::from("clean");
        body.push(HOMOGLYPHS[0].1);
        assert!(has_any_noise(&body));
    }

    #[test]
    fn has_any_noise_is_false_on_pure_ascii_body() {
        assert!(!has_any_noise("abcdefghijklmnopqrstuvwxyz"));
    }

    #[test]
    fn round_trip_holds_for_many_epochs_and_body_lengths() {
        for epoch in 0u64..32 {
            for len in [1usize, 2, 5, 17, 64, 256, 1024] {
                // Build an ASCII body of the requested length using
                // every lowercase letter.
                let body: String = (0..len)
                    .map(|i| {
                        let idx = (i + epoch as usize) % 26;
                        char::from(b'a' + u8::try_from(idx).unwrap())
                    })
                    .collect();
                let noisy = inject_noise(&body, epoch);
                let clean = strip_noise(&noisy);
                assert_eq!(
                    clean, body,
                    "round-trip failed at epoch={epoch}, len={len}"
                );
            }
        }
    }

    #[test]
    fn injection_is_strictly_larger_than_input_for_nonempty_body() {
        // Any body of length >= ZERO_WIDTH_PERIOD * 2 + 1 must have
        // at least one injection on average.  We check a long
        // body to make this robust against the wide PRNG variance.
        let body = "z".repeat(1024);
        let noisy = inject_noise(&body, 0);
        assert!(noisy.chars().count() > body.chars().count());
    }

    #[test]
    fn noise_does_not_alter_already_noisy_body_into_invalid_state() {
        // Stripping a stripped body returns the same body — the
        // strip is content-blind so it cannot introduce data.
        let body = "thequickbrownfox";
        let noisy = inject_noise(body, 13);
        let clean1 = strip_noise(&noisy);
        let clean2 = strip_noise(&clean1);
        assert_eq!(clean1, body);
        assert_eq!(clean2, body);
    }

    #[test]
    fn zero_width_codepoints_match_documented_set() {
        assert_eq!(ZERO_WIDTH_CODEPOINTS[0], '\u{200B}');
        assert_eq!(ZERO_WIDTH_CODEPOINTS[1], '\u{200C}');
        assert_eq!(ZERO_WIDTH_CODEPOINTS[2], '\u{200D}');
    }

    #[test]
    fn homoglyph_set_matches_documented_codepoints() {
        let pairs: Vec<(char, u32)> =
            HOMOGLYPHS.iter().map(|&(l, c)| (l, c as u32)).collect();
        assert_eq!(
            pairs,
            vec![
                ('a', 0x0430),
                ('c', 0x0441),
                ('e', 0x0435),
                ('i', 0x0456),
                ('o', 0x043E),
                ('p', 0x0440),
                ('x', 0x0445),
                ('y', 0x0443),
            ]
        );
    }
}
