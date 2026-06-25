//! Layer 4 — code-order reorder with position markers.
//!
//! # What this defeats
//!
//! Idiomatic file ordering (imports first, helpers next, main last)
//! gives an attacker who has cached "shape of a typical Python file"
//! a free oracle on where to insert exploits.  L4 splits the source
//! into top-level chunks, prefixes each with a position marker
//! (`__bbnpos<N>__`), and shuffles chunk order deterministically by
//! epoch.  The trusted-tier unscrambler reads the markers and restores
//! the original order before emission.
//!
//! # Composition with L2 / L3
//!
//! Scramble pipeline order:
//!   1. tokenize
//!   2. **L4: insert markers + shuffle chunks** (this module)
//!   3. L2: dynamic identifier scramble (markers go through L2 like
//!      any other word — they collide-test inside `IdentifierMapping`)
//!   4. L3: whitespace-as-words
//!
//! Unscramble pipeline order is the inverse:
//!   1. L3: unscramble whitespace
//!   2. L2: unscramble identifiers (markers reappear as plain words)
//!   3. **L4: sort by marker, strip markers** (this module)
//!   4. emit source
//!
//! # Threat model boundary
//!
//! - Defeats: positional fingerprinting of typical file shapes.
//! - Does NOT defeat: an attacker who already knows the per-host
//!   secret (they recover the L2 mapping and read the markers).
//!   L4 raises cost on the structural-template path, nothing else.
//!
//! # MVP scope
//!
//! - Chunks are split at top-level newlines (depth 0, not immediately
//!   followed by `IndentOpen`).  Multi-line constructs (def / class
//!   blocks, if/else, etc.) are kept intact as one chunk.
//! - Shuffle is seeded deterministically by the L2 epoch; no
//!   per-host secret is required at this layer (security comes from
//!   markers being unreadable without the L2 mapping).
//! - Markers are plain `Token::Word` bodies of the form
//!   `__bbnpos<N>__`.  No special handling in L2/L3 needed.

use crate::tokens::{Token, WhitespaceKind};

/// Marker prefix; uniquely identifies an L4 position marker in the
/// unscramble pass.  The numeric body and trailing `__` follow.
const MARKER_PREFIX: &str = "__bbnpos";
/// Marker suffix.  The pair `<prefix><digits><suffix>` is unambiguous
/// because the digits run is non-empty and contains no other
/// underscores.
const MARKER_SUFFIX: &str = "__";

/// Format a position marker token body for chunk index `n`.
#[must_use]
pub fn marker_body(n: usize) -> String {
    format!("{MARKER_PREFIX}{n}{MARKER_SUFFIX}")
}

/// Parse a position marker body into its chunk index, if it matches
/// the marker shape.
#[must_use]
pub fn parse_marker(body: &str) -> Option<usize> {
    let inner = body.strip_prefix(MARKER_PREFIX)?.strip_suffix(MARKER_SUFFIX)?;
    if inner.is_empty() || !inner.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    inner.parse().ok()
}

/// Split a token stream into top-level chunks.
///
/// A chunk boundary is a `Newline` at indent depth 0 whose immediately
/// following token is NOT `IndentOpen`.  The boundary `Newline` is
/// included as the LAST token of the chunk before it (so chunks own
/// their trailing newline).  Trailing `IndentClose` runs at end-of-
/// file attach to the chunk that owns the matching open.
///
/// Returns a `Vec<Vec<Token>>` where each inner vec is one chunk.  If
/// the input has no chunk boundaries, returns a single chunk
/// containing the entire input.
fn split_chunks(tokens: Vec<Token>) -> Vec<Vec<Token>> {
    let mut chunks: Vec<Vec<Token>> = Vec::new();
    let mut current: Vec<Token> = Vec::new();
    let mut depth: i64 = 0;

    // Two kinds of chunk boundary:
    //   1. Newline at depth 0 (statement terminator at top level).
    //   2. IndentClose that brings depth back to 0 (top-level
    //      statement that owned an indented block just ended; the
    //      tokenizer emits no trailing Newline after the closing
    //      dedent at EOF, and even mid-file the next token after
    //      such an IndentClose is the start of a NEW top-level
    //      statement, not a continuation of the closing one).
    // Single-pass with std::mem::take + a post-pass merge of chunks
    // starting with IndentOpen handles the `def f():\n    body` case
    // where the newline after `def f():` is at depth 0 but opens an
    // indented block belonging to the same logical chunk.
    for tok in tokens {
        let is_open = matches!(
            &tok,
            Token::Whitespace(WhitespaceKind::IndentOpen)
        );
        let is_close = matches!(
            &tok,
            Token::Whitespace(WhitespaceKind::IndentClose)
        );
        let is_newline = matches!(
            &tok,
            Token::Whitespace(WhitespaceKind::Newline)
        );
        if is_open {
            depth += 1;
        }
        current.push(tok);
        if is_close {
            depth -= 1;
            if depth == 0 {
                chunks.push(std::mem::take(&mut current));
                continue;
            }
        }
        if is_newline && depth == 0 {
            chunks.push(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        chunks.push(current);
    }

    // Post-pass: merge any chunk that starts with `IndentOpen` into
    // the previous chunk.  This handles the `def f():\n    body`
    // case where the newline after `def f():` is at depth 0 but
    // opens an indented block belonging to the same logical chunk.
    let mut merged: Vec<Vec<Token>> = Vec::with_capacity(chunks.len());
    for chunk in chunks {
        let starts_with_indent_open = matches!(
            chunk.first(),
            Some(Token::Whitespace(WhitespaceKind::IndentOpen))
        );
        if starts_with_indent_open {
            if let Some(prev) = merged.last_mut() {
                prev.extend(chunk);
                continue;
            }
        }
        merged.push(chunk);
    }
    merged
}

/// Tiny xorshift64 seeded by epoch.  Deterministic, stable across
/// runs; carries zero security weight (the marker, not the shuffle
/// permutation, is the secret).
struct XorShift64(u64);

impl XorShift64 {
    fn from_epoch(epoch: u64) -> Self {
        // Mix epoch with a fixed constant to avoid the all-zero seed
        // (xorshift would lock at 0).  The constant is the v2 layer-4
        // domain tag, hashed to a u64.
        let seed = epoch
            .wrapping_mul(0x9E37_79B9_7F4A_7C15)
            ^ 0x517C_C1B7_2722_0A95;
        Self(if seed == 0 { 0xDEAD_BEEF_CAFE_BABE } else { seed })
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
        // Unbiased mod; for our small `n` (chunks per file) the modulo
        // bias is negligible.  Used only for chunk reorder shuffle.
        (self.next_u64() as usize) % exclusive_upper.max(1)
    }
}

/// Build a permutation of `[0, n)` using Fisher-Yates seeded by epoch.
///
/// `permutation[i]` = original chunk index now placed at position `i`.
fn shuffle_permutation(n: usize, epoch: u64) -> Vec<usize> {
    let mut perm: Vec<usize> = (0..n).collect();
    let mut rng = XorShift64::from_epoch(epoch);
    // Fisher-Yates from the end.
    for i in (1..n).rev() {
        let j = rng.gen_range(i + 1);
        perm.swap(i, j);
    }
    perm
}

/// Apply L4: insert position markers, shuffle chunk order.
///
/// Empty input or single-chunk input is returned unchanged (no
/// markers inserted; shuffling one chunk is a no-op).  In particular
/// scramble→unscramble is the identity on inputs with no top-level
/// chunk boundaries.
#[must_use]
pub fn scramble_chunks(tokens: Vec<Token>, epoch: u64) -> Vec<Token> {
    let chunks = split_chunks(tokens);
    if chunks.len() < 2 {
        return chunks.into_iter().flatten().collect();
    }
    let n = chunks.len();
    let perm = shuffle_permutation(n, epoch);

    // Pre-build the marked chunks in original order; then place them
    // according to the permutation.
    let mut marked: Vec<Vec<Token>> = Vec::with_capacity(n);
    for (orig_idx, chunk) in chunks.into_iter().enumerate() {
        let mut m: Vec<Token> = Vec::with_capacity(chunk.len() + 2);
        m.push(Token::word(&marker_body(orig_idx)));
        m.push(Token::whitespace(WhitespaceKind::Space));
        m.extend(chunk);
        marked.push(m);
    }
    let mut shuffled: Vec<Vec<Token>> = Vec::with_capacity(n);
    for &orig_idx in &perm {
        shuffled.push(std::mem::take(&mut marked[orig_idx]));
    }
    shuffled.into_iter().flatten().collect()
}

/// Apply L4 inverse: read markers, sort chunks back to original
/// order, strip markers.
///
/// Inputs with no markers are returned unchanged (handles the
/// single-chunk no-op case from [`scramble_chunks`] and streams that
/// never went through L4 at all).  Mixed inputs (some chunks with
/// markers, some without) place unmarked chunks at the end in their
/// observed order — defence-in-depth against a corrupted L4 pass.
#[must_use]
pub fn unscramble_chunks(tokens: Vec<Token>) -> Vec<Token> {
    if !has_any_marker(&tokens) {
        return tokens;
    }
    let chunks = split_chunks(tokens);
    let mut positioned: Vec<(usize, Vec<Token>)> = Vec::with_capacity(chunks.len());
    let mut trailing_unmarked: Vec<Token> = Vec::new();
    for chunk in chunks {
        match strip_leading_marker(chunk) {
            Ok((idx, rest)) => positioned.push((idx, rest)),
            Err(original) => trailing_unmarked.extend(original),
        }
    }
    positioned.sort_by_key(|(i, _)| *i);
    let mut out: Vec<Token> = positioned.into_iter().flat_map(|(_, c)| c).collect();
    out.extend(trailing_unmarked);
    out
}

/// True if the token stream contains at least one L4 position marker.
/// Cheap one-pass scan; the caller uses this to decide whether to
/// invoke [`unscramble_chunks`] at all (the no-marker case is the
/// L4-disabled pass-through).
#[must_use]
pub fn has_any_marker(tokens: &[Token]) -> bool {
    tokens.iter().any(|t| matches!(t, Token::Word(b) if parse_marker(b).is_some()))
}

/// Strip a leading position-marker word (and the trailing space
/// inserted next to it) from a chunk.  Returns the original chunk
/// in the `Err` arm if no marker is present, so the caller can
/// preserve its tokens.
fn strip_leading_marker(chunk: Vec<Token>) -> Result<(usize, Vec<Token>), Vec<Token>> {
    let idx = match chunk.first() {
        Some(Token::Word(body)) => match parse_marker(body) {
            Some(i) => i,
            None => return Err(chunk),
        },
        _ => return Err(chunk),
    };
    let mut iter = chunk.into_iter();
    let _marker = iter.next();
    let mut rest: Vec<Token> = iter.collect();
    if matches!(
        rest.first(),
        Some(Token::Whitespace(WhitespaceKind::Space))
    ) {
        rest.remove(0);
    }
    Ok((idx, rest))
}

#[cfg(test)]
mod tests {
    use super::{
        has_any_marker, marker_body, parse_marker, scramble_chunks,
        unscramble_chunks,
    };
    use crate::python_tokenizer::tokenize;
    use crate::tokens::Token;

    #[test]
    fn marker_body_and_parse_roundtrip() {
        for n in [0usize, 1, 7, 42, 99_999] {
            assert_eq!(parse_marker(&marker_body(n)), Some(n));
        }
    }

    #[test]
    fn parse_marker_rejects_nonmarkers() {
        for bad in ["", "foo", "__bbnpos__", "__bbnposABC__", "bbnpos0__", "__bbnpos0"]
        {
            assert_eq!(parse_marker(bad), None, "should reject {bad:?}");
        }
    }

    fn render_for_compare(tokens: &[Token]) -> Vec<&str> {
        tokens
            .iter()
            .filter_map(|t| match t {
                Token::Word(b) => Some(b.as_str()),
                Token::Whitespace(_) => None,
            })
            .collect()
    }

    #[test]
    fn empty_input_roundtrips() {
        let scrambled = scramble_chunks(Vec::new(), 0);
        assert!(scrambled.is_empty());
        assert!(!has_any_marker(&scrambled));
    }

    #[test]
    fn single_chunk_is_unchanged_and_has_no_markers() {
        let src = "x = 1\n";
        let tokens = tokenize(src);
        let scrambled = scramble_chunks(tokens.clone(), 0);
        assert!(
            !has_any_marker(&scrambled),
            "single-chunk input must not get a marker",
        );
        assert_eq!(scrambled, tokens, "single-chunk input must be unchanged");
    }

    #[test]
    fn multi_chunk_roundtrips_in_original_order() {
        let src = "import foo\nx = 1\ny = 2\nz = 3\n";
        let tokens = tokenize(src);
        let scrambled = scramble_chunks(tokens.clone(), 42);
        assert!(has_any_marker(&scrambled), "multi-chunk input must have markers");
        let unscrambled = unscramble_chunks(scrambled);
        assert_eq!(unscrambled, tokens, "round-trip must preserve token order");
    }

    #[test]
    fn def_block_kept_intact_after_scramble() {
        // The chunks: `import foo\n`, `def f():\n    return 1\n`, `y = f()\n`.
        let src = "import foo\ndef f():\n    return 1\ny = f()\n";
        let tokens = tokenize(src);
        let scrambled = scramble_chunks(tokens.clone(), 7);
        let unscrambled = unscramble_chunks(scrambled);
        assert_eq!(unscrambled, tokens);
    }

    #[test]
    fn class_block_kept_intact() {
        let src = "\
class C:
    def m(self):
        return 1
x = 1
";
        let tokens = tokenize(src);
        let scrambled = scramble_chunks(tokens.clone(), 9);
        let unscrambled = unscramble_chunks(scrambled);
        assert_eq!(unscrambled, tokens);
    }

    #[test]
    fn shuffle_is_deterministic_per_epoch() {
        let src = "a = 1\nb = 2\nc = 3\nd = 4\ne = 5\nf = 6\n";
        let tokens = tokenize(src);
        let a = scramble_chunks(tokens.clone(), 12345);
        let b = scramble_chunks(tokens.clone(), 12345);
        assert_eq!(a, b, "same epoch must produce same shuffle");
    }

    #[test]
    fn different_epochs_likely_produce_different_shuffles() {
        // With six chunks (720 perms) two random epochs should
        // produce different orders with very high probability.
        let src = "a = 1\nb = 2\nc = 3\nd = 4\ne = 5\nf = 6\n";
        let tokens = tokenize(src);
        let a = scramble_chunks(tokens.clone(), 1);
        let b = scramble_chunks(tokens, 2);
        assert_ne!(a, b, "different epochs should produce different shuffles");
    }

    #[test]
    fn shuffle_actually_permutes_at_some_epoch() {
        // Confirm the shuffle isn't a no-op identity for some seed.
        let src = "a = 1\nb = 2\nc = 3\nd = 4\ne = 5\nf = 6\n";
        let tokens = tokenize(src);
        // Try a handful of epochs until we find one that reorders.
        let mut found_reorder = false;
        for epoch in 0..32 {
            let scrambled = scramble_chunks(tokens.clone(), epoch);
            // After stripping markers, compare order.
            let unmarked: Vec<&str> = scrambled
                .iter()
                .filter_map(|t| match t {
                    Token::Word(b) if super::parse_marker(b).is_none() => {
                        Some(b.as_str())
                    }
                    _ => None,
                })
                .collect();
            let original: Vec<&str> = render_for_compare(&tokens);
            if unmarked != original {
                found_reorder = true;
                break;
            }
        }
        assert!(found_reorder, "no epoch in [0, 32) actually reorders");
    }
}
