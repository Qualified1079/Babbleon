//! Layer 5 — decoy injection.
//!
//! # What this defeats
//!
//! An attacker who knows the rotation window (a few seconds to tens
//! of seconds) and tries to insert a working exploit in that window
//! must first locate the live code among injected decoys.  L5
//! sprinkles per-epoch decoy `Word` tokens at random positions in
//! the token stream; the trusted-tier unscrambler strips them by
//! recognizing the `__bbndecoy<N>__` marker prefix before emission.
//!
//! # Composition
//!
//! Scramble pipeline:
//!   1. tokenize
//!   2. L4: chunk reorder + position markers
//!   3. **L5: decoy injection** (this module)
//!   4. L2: dynamic identifier scramble (decoy markers go through
//!      L2 like any other word)
//!   5. L3: whitespace-as-words
//!
//! Unscramble pipeline:
//!   1. L3: unscramble whitespace
//!   2. L2: unscramble identifiers (decoy markers reappear)
//!   3. **L5: strip decoy tokens** (this module)
//!   4. L4: sort by position marker, strip markers
//!   5. emit source
//!
//! # Threat model boundary
//!
//! - Defeats: in-window exploit insertion that doesn't first locate
//!   the live code in the wall of compounds.
//! - Does NOT defeat: an attacker who can read the L2 mapping (they
//!   recover the decoy markers and strip them just like the
//!   trusted tier does).  L5 raises cost on the in-window insertion
//!   path, nothing else.
//!
//! # MVP scope
//!
//! - Decoy count is proportional to the original token stream length
//!   (`DECOY_FRACTION` ≈ 25%).  Sufficient to noticeably grow the
//!   compound wall without ballooning the unscrambled-side work.
//! - Decoy positions are deterministic by `epoch` (xorshift seed).
//! - Decoy bodies use a recognizable shape `__bbndecoy<N>__` so the
//!   strip pass is a simple prefix/suffix match.
//! - Decoys are placed only at the TOP LEVEL (depth 0) and only
//!   between tokens — never inside an indented block, never inside
//!   a string literal (the tokenizer guarantees Word tokens hold
//!   string literals atomically).

use crate::tokens::{Token, WhitespaceKind};

/// Fraction of the original token-stream length to inject as decoys,
/// expressed as `decoys = tokens.len() / DECOY_DIVISOR`.  4 → 25%.
const DECOY_DIVISOR: usize = 4;

/// Prefix of every decoy marker body.
const DECOY_PREFIX: &str = "__bbndecoy";
/// Suffix of every decoy marker body.
const DECOY_SUFFIX: &str = "__";

/// True if `body` looks like an L5 decoy marker.
#[must_use]
pub fn is_decoy_body(body: &str) -> bool {
    let Some(inner) = body
        .strip_prefix(DECOY_PREFIX)
        .and_then(|s| s.strip_suffix(DECOY_SUFFIX))
    else {
        return false;
    };
    !inner.is_empty() && inner.chars().all(|c| c.is_ascii_digit())
}

/// Format the body for the `n`-th decoy token in this file.
#[must_use]
pub fn decoy_body(n: usize) -> String {
    format!("{DECOY_PREFIX}{n}{DECOY_SUFFIX}")
}

/// Tiny xorshift64 seeded by epoch + a layer-5 domain tag.
/// Bench-deterministic; carries zero security weight.
struct XorShift64(u64);

impl XorShift64 {
    fn from_epoch(epoch: u64) -> Self {
        let seed = epoch
            .wrapping_mul(0x9E37_79B9_7F4A_7C15)
            ^ 0x2B5C_1F3A_4E7C_9D11;
        Self(if seed == 0 { 0xCAFE_F00D_DEAD_BEEF } else { seed })
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
        (self.next_u64() as usize) % exclusive_upper.max(1)
    }
}

/// Apply L5: inject `tokens.len() / DECOY_DIVISOR` decoy tokens at
/// pseudorandom top-level positions.  Returns the augmented stream.
///
/// Decoy positions are chosen only at depth 0 (i.e. between tokens
/// where the cumulative `IndentOpen` count equals the cumulative
/// `IndentClose` count); injecting inside an indented block would
/// risk producing tokens at an unexpected indent level after L3
/// round-trip (the L3 unscrambler canonicalises indents from
/// `IndentOpen`/`IndentClose` markers, which decoys do not produce).
///
/// Empty input is returned unchanged.
#[must_use]
pub fn inject_decoys(tokens: Vec<Token>, epoch: u64) -> Vec<Token> {
    let n_decoys = tokens.len() / DECOY_DIVISOR;
    if n_decoys == 0 {
        return tokens;
    }

    // Enumerate the depth-0 insertion candidate positions: indices
    // `i` such that `tokens[..i]` has equal `IndentOpen` and
    // `IndentClose` counts.
    let mut candidates: Vec<usize> = Vec::new();
    let mut depth: i64 = 0;
    candidates.push(0); // start of file is depth 0
    for (i, t) in tokens.iter().enumerate() {
        match t {
            Token::Whitespace(WhitespaceKind::IndentOpen) => depth += 1,
            Token::Whitespace(WhitespaceKind::IndentClose) => depth -= 1,
            _ => {}
        }
        if depth == 0 {
            candidates.push(i + 1);
        }
    }

    let mut rng = XorShift64::from_epoch(epoch);
    // Build a list of (position, decoy) pairs; sort by position
    // descending so we can splice in without invalidating later
    // indices.
    let mut placements: Vec<(usize, Token)> = (0..n_decoys)
        .map(|n| {
            let pos = candidates[rng.gen_range(candidates.len())];
            (pos, Token::word(&decoy_body(n)))
        })
        .collect();
    placements.sort_by_key(|(p, _)| std::cmp::Reverse(*p));

    let mut out = tokens;
    for (pos, decoy) in placements {
        // Pad the decoy with Space on BOTH sides.  L3 needs a
        // whitespace boundary between any two Word tokens, otherwise
        // its greedy prefix-match would merge the decoy and the
        // surrounding token into one mega-compound that neither
        // `unscramble_identifiers` nor `strip_decoys` would recognise.
        // The strip pass eats both adjacent spaces (one before, one
        // after) when it removes the decoy.
        out.insert(pos, Token::whitespace(WhitespaceKind::Space));
        out.insert(pos, decoy);
        out.insert(pos, Token::whitespace(WhitespaceKind::Space));
    }
    out
}

/// Apply L5 inverse: strip every decoy token (and the adjacent
/// padding Spaces the injector placed on both sides) from the stream.
///
/// Tokens without decoy markers are unchanged.  Safe to call on a
/// stream that never went through `inject_decoys`.
#[must_use]
pub fn strip_decoys(tokens: Vec<Token>) -> Vec<Token> {
    let mut out: Vec<Token> = Vec::with_capacity(tokens.len());
    let mut iter = tokens.into_iter().peekable();
    while let Some(tok) = iter.next() {
        if let Token::Word(body) = &tok {
            if is_decoy_body(body) {
                // Eat one trailing Space (the injector always pairs
                // decoy + trailing Space) AND remove the immediately
                // preceding Space from `out` if present (the
                // injector also placed a leading Space).
                if matches!(
                    iter.peek(),
                    Some(Token::Whitespace(WhitespaceKind::Space))
                ) {
                    iter.next();
                }
                if matches!(
                    out.last(),
                    Some(Token::Whitespace(WhitespaceKind::Space))
                ) {
                    out.pop();
                }
                continue;
            }
        }
        out.push(tok);
    }
    out
}

/// True if `tokens` contains at least one decoy marker.
#[must_use]
pub fn has_any_decoy(tokens: &[Token]) -> bool {
    tokens
        .iter()
        .any(|t| matches!(t, Token::Word(b) if is_decoy_body(b)))
}

#[cfg(test)]
mod tests {
    use super::{
        decoy_body, has_any_decoy, inject_decoys, is_decoy_body, strip_decoys,
    };
    use crate::python_tokenizer::tokenize;
    use crate::tokens::Token;

    #[test]
    fn decoy_body_and_is_decoy_body_roundtrip() {
        for n in [0usize, 1, 7, 99, 12_345] {
            assert!(is_decoy_body(&decoy_body(n)));
        }
    }

    #[test]
    fn is_decoy_body_rejects_nonmatches() {
        for bad in [
            "", "foo", "__bbndecoy__", "__bbndecoyXYZ__",
            "bbndecoy0__", "__bbndecoy0", "__bbnpos0__",
        ] {
            assert!(!is_decoy_body(bad), "should reject {bad:?}");
        }
    }

    #[test]
    fn empty_input_returns_unchanged() {
        assert!(inject_decoys(Vec::new(), 0).is_empty());
        assert!(strip_decoys(Vec::new()).is_empty());
    }

    #[test]
    fn tiny_input_below_threshold_returns_unchanged() {
        // Three tokens: tokens.len() / 4 = 0 decoys.
        let toks = vec![
            Token::word("a"),
            Token::word("b"),
            Token::word("c"),
        ];
        let injected = inject_decoys(toks.clone(), 0);
        assert_eq!(injected, toks, "no decoys injected when count rounds to 0");
    }

    #[test]
    fn injection_increases_token_count() {
        let src = "import foo\nx = 1\ny = 2\nz = 3\nq = 4\nr = 5\n";
        let toks = tokenize(src);
        let injected = inject_decoys(toks.clone(), 7);
        assert!(
            injected.len() > toks.len(),
            "decoys should grow the stream",
        );
    }

    #[test]
    fn inject_then_strip_recovers_original() {
        let src = "import foo\nx = 1\ny = 2\nz = 3\nq = 4\nr = 5\n";
        let toks = tokenize(src);
        let injected = inject_decoys(toks.clone(), 7);
        assert!(has_any_decoy(&injected));
        let stripped = strip_decoys(injected);
        assert_eq!(stripped, toks);
    }

    #[test]
    fn injection_is_deterministic_per_epoch() {
        let src = "a = 1\nb = 2\nc = 3\nd = 4\ne = 5\nf = 6\n";
        let toks = tokenize(src);
        let a = inject_decoys(toks.clone(), 42);
        let b = inject_decoys(toks, 42);
        assert_eq!(a, b);
    }

    #[test]
    fn different_epochs_likely_produce_different_injections() {
        let src = "a = 1\nb = 2\nc = 3\nd = 4\ne = 5\nf = 6\n";
        let toks = tokenize(src);
        let a = inject_decoys(toks.clone(), 1);
        let b = inject_decoys(toks, 2);
        assert_ne!(a, b);
    }

    #[test]
    fn decoys_never_land_inside_indented_block() {
        // def block has tokens at depth 1; verify no decoy ends up
        // between IndentOpen and IndentClose.
        let src = "def f():\n    return 1\n    return 2\n    return 3\n";
        let toks = tokenize(src);
        let injected = inject_decoys(toks, 0);
        use crate::tokens::WhitespaceKind;
        let mut depth: i64 = 0;
        for t in &injected {
            match t {
                Token::Whitespace(WhitespaceKind::IndentOpen) => depth += 1,
                Token::Whitespace(WhitespaceKind::IndentClose) => depth -= 1,
                Token::Word(b) if is_decoy_body(b) => {
                    assert_eq!(
                        depth, 0,
                        "decoy at depth {depth}: {b}",
                    );
                }
                _ => {}
            }
        }
    }

    #[test]
    fn strip_passes_through_when_no_decoys_present() {
        let src = "import foo\nx = 1\n";
        let toks = tokenize(src);
        assert_eq!(strip_decoys(toks.clone()), toks);
    }
}
