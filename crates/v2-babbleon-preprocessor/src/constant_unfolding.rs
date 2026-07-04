//! Layer 9 — constant unfolding.
//!
//! # What this defeats
//!
//! A bare integer literal (`port = 22`, `retries = 3`) is a free gift
//! to an attacker skimming a scrambled file: literal-value context is
//! exactly the kind of anchor an LLM attacker uses to re-orient after
//! stripping the wordlist noise ("this must be the listen port").  L9
//! replaces every whitespace-isolated decimal-integer `Word` token
//! with a self-describing marker that the trusted-tier unscrambler
//! evaluates back to the exact original literal before emission. The
//! *scrambled file on disk* never contains the literal in plain
//! decimal; only the marker (which — like every other layer's marker
//! — goes through L2 identifier scrambling like any other token, so
//! the final on-disk byte string does not even show the marker shape,
//! only whatever alias L2 assigned it).
//!
//! # Composition
//!
//! Scramble pipeline:
//!
//!   tokenize → **L9** → L4 → L5 → L2 → L3 → L6 → L12 → write
//!
//! Unscramble pipeline:
//!
//!   read → L12⁻¹ → L6⁻¹ → L3⁻¹ → L2⁻¹ → L5⁻¹ → L4⁻¹ → **L9⁻¹** → emit
//!
//! L9 runs first (right after tokenize) on scramble and last (right
//! before token-to-source emission) on unscramble — the outermost
//! layer pair, mirroring how L4/L5 bracket the L2/L3 core from the
//! other side.  Placement relative to L4/L5 does not matter for
//! correctness (chunk reorder and decoy injection are blind to `Word`
//! content), so the outermost position was chosen for the simplest
//! possible interaction: L9 never has to reason about position
//! markers or decoy bodies, and they never have to reason about it.
//!
//! # Design note — deviation from `docs/v2/obfuscation-landscape.md`
//!
//! The research note's illustrative example (`port = 22` →
//! `port = some_compound * another - third`) sketches unfolding into
//! *live arithmetic the interpreter itself evaluates*, with the
//! sub-terms drawn from the wordlist-scrambled identifier pool. That
//! shape requires injecting new variable-defining statements
//! somewhere the interpreter will execute them before the use site —
//! a real control-flow/scoping problem (module level? enclosing
//! function? before or after an unrelated chunk reorder moves things
//! around?) that the MVP whitespace-delimited tokenizer has no safe
//! way to reason about.
//!
//! This implementation instead evaluates the arithmetic **in the
//! preprocessor**, at unscramble time, the same way L4's position
//! markers and L5's decoy bodies are resolved and stripped before
//! emission — no new statements, no scoping question, and the
//! interpreter only ever sees the exact original literal. The
//! opacity benefit (attacker cannot glance at a compound and read
//! "this is 22") is unchanged; what's dropped is the (cosmetic, not
//! security-relevant — see the module doc above) idea of leaving the
//! arithmetic live in the emitted program. If a future session wants
//! genuinely-live unfolded arithmetic, it needs a real AST-aware
//! tokenizer first; filed as a note here rather than attempted with
//! the whitespace tokenizer's known limitations
//! (`python_tokenizer::MVP_LIMITATIONS`).
//!
//! # Threat-model boundary
//!
//! - Defeats: naive literal-value skimming as a re-orientation anchor
//!   after wordlist noise is stripped.
//! - Does NOT defeat: an attacker who has the per-host secret and the
//!   L2 mapping — they recover the exact marker text like any other
//!   token and evaluate it themselves. Like L4/L5/L6/L12, L9 raises
//!   the cost of the naive path; it does not change the trust
//!   boundary (the daemon never leaves the trusted tier).
//!
//! # MVP scope
//!
//! - Only bare decimal-integer `Word` tokens are eligible: the entire
//!   token text must match `^[0-9]+$` (guarded further by a
//!   round-trip check against `to_string()` so an exotic form like a
//!   leading-zero literal is left untouched rather than silently
//!   losing its original spelling). Because the MVP tokenizer does
//!   not split operators from adjacent identifiers
//!   (`python_tokenizer::MVP_LIMITATIONS` #3), this in practice only
//!   catches literals with whitespace on both sides — `x = 22` and
//!   `return 22`, not `f(22)` or `x[0]`. Narrower coverage than a
//!   real AST pass would get, but zero risk of corrupting a literal
//!   embedded in a larger opaque word.
//! - Value range `[MIN_FOLD_VALUE, MAX_FOLD_VALUE]` — `0` and `1` are
//!   skipped (common, low value to hide, and disproportionately
//!   noisy to unfold everywhere they appear); values above
//!   `MAX_FOLD_VALUE` are skipped as a simple sanity bound, not a
//!   security-relevant cutoff.
//! - Two decomposition shapes selected by a per-occurrence coin flip
//!   from a per-epoch PRNG: `a + b = n` (both operands in `[1, n-1]`)
//!   and `c - d = n` (`d` a small random offset, `c = n + d`). Every
//!   eligible literal is folded — no probabilistic skip — since
//!   there's no cost to folding every one and doing so maximizes the
//!   number of literals no longer visible in plaintext.
//! - The marker is fully self-describing (the two operands are
//!   encoded directly in its text); unscramble does not replay the
//!   PRNG. This is a deliberate difference from L4/L5/L6, which are
//!   PRNG-driven table lookups because they need to reconstruct
//!   *positions*, not just a value round-trip. Text-level markers are
//!   simpler and carry zero determinism-mismatch risk between the
//!   scramble and unscramble sides.

use crate::tokens::Token;

/// Smallest literal value eligible for folding.
///
/// `0` and `1` are common, cheap to recognize even scrambled (an
/// attacker gains little from knowing "some literal is 0 or 1"), and
/// folding every occurrence would add noise disproportionate to the
/// value hidden. Anything `>= MIN_FOLD_VALUE` is folded.
const MIN_FOLD_VALUE: u64 = 2;

/// Largest literal value eligible for folding.
///
/// A simple sanity bound (covers any realistic port, size, timeout,
/// or count constant) — not a security-relevant cutoff. Keeps the
/// arithmetic trivially within `u64` with enormous headroom and
/// avoids folding pathological huge integer literals some source
/// might contain for unrelated reasons.
const MAX_FOLD_VALUE: u64 = 1_000_000_000;

/// Prefix of every L9 folded-constant marker body.
const FOLD_PREFIX: &str = "__bbnfold";
/// Suffix of every L9 folded-constant marker body.
const FOLD_SUFFIX: &str = "__";
/// Separator between the two encoded operands.
const OPERAND_SEP: char = 'x';
/// Tag byte selecting the `a + b = n` decomposition.
const TAG_ADD: char = 'a';
/// Tag byte selecting the `c - d = n` decomposition.
const TAG_SUB: char = 's';

/// Upper bound (exclusive) on the random subtraction offset `d` in
/// the `c - d = n` decomposition. Arbitrary; keeps `c`'s digit count
/// close to `n`'s rather than ballooning it.
const SUB_OFFSET_BOUND: u64 = 1000;

/// Tiny xorshift64 PRNG with an L9-specific domain tag.
///
/// Carries zero security weight — same rationale as every other
/// layer's PRNG (L5, L6, L12): variety across occurrences, not
/// secrecy of the decomposition shape. Unlike those layers, L9's
/// unfold side never re-seeds this PRNG at all (the marker is
/// self-describing), so there is no determinism-mismatch class to
/// worry about here.
struct XorShift64(u64);

impl XorShift64 {
    fn from_epoch(epoch: u64) -> Self {
        let seed = epoch
            .wrapping_mul(0xA24B_AED4_963E_E407)
            ^ 0x9E65_1F0C_3B7A_D2E1;
        Self(if seed == 0 { 0xD1CE_FACE_B00C_1E55 } else { seed })
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    /// Uniform value in `[0, exclusive_upper)`, computed at `u64`
    /// width throughout (see L5/L6's identical note: truncating to a
    /// narrower width before the mod would change the sequence on a
    /// narrower-pointer-width host).
    fn gen_range_u64(&mut self, exclusive_upper: u64) -> u64 {
        let modulus = exclusive_upper.max(1);
        self.next_u64() % modulus
    }

    /// Fair coin.
    fn coin(&mut self) -> bool {
        self.gen_range_u64(2) == 0
    }
}

/// Parse `s` as a foldable literal, returning its value.
///
/// Requires the *entire* string to be ASCII decimal digits, that the
/// value round-trips exactly through `to_string()` (rejects exotic
/// spellings like a leading-zero literal, which would lose its
/// original spelling on unfold), and that the value falls in
/// `[MIN_FOLD_VALUE, MAX_FOLD_VALUE]`.
fn parse_foldable_literal(s: &str) -> Option<u64> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let n: u64 = s.parse().ok()?;
    if n.to_string() != s {
        return None;
    }
    if !(MIN_FOLD_VALUE..=MAX_FOLD_VALUE).contains(&n) {
        return None;
    }
    Some(n)
}

/// Format the marker body that folds `n` using the `a + b = n` shape.
fn add_marker(a: u64, b: u64) -> String {
    format!("{FOLD_PREFIX}{TAG_ADD}{a}{OPERAND_SEP}{b}{FOLD_SUFFIX}")
}

/// Format the marker body that folds `n` using the `c - d = n` shape.
fn sub_marker(c: u64, d: u64) -> String {
    format!("{FOLD_PREFIX}{TAG_SUB}{c}{OPERAND_SEP}{d}{FOLD_SUFFIX}")
}

/// Fold `n` into a marker body, choosing a decomposition shape with
/// `rng`.
fn fold_marker(n: u64, rng: &mut XorShift64) -> String {
    if rng.coin() {
        // a + b = n, both operands in [1, n-1]. Requires n >= 2,
        // guaranteed by MIN_FOLD_VALUE.
        let a = rng.gen_range_u64(n - 1) + 1;
        let b = n - a;
        add_marker(a, b)
    } else {
        // c - d = n, d a small random positive offset.
        let d = rng.gen_range_u64(SUB_OFFSET_BOUND) + 1;
        let c = n + d;
        sub_marker(c, d)
    }
}

/// Parse digits after stripping the tag byte; `None` on any
/// malformed operand (empty, non-digit, or overflowing `u64`).
fn parse_operand(s: &str) -> Option<u64> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

/// Evaluate a folded-constant marker body back to its literal value.
///
/// Returns `None` if `body` does not match the exact marker shape —
/// callers use this to distinguish a real L9 marker from ordinary
/// user text that happens to start with the prefix.
fn evaluate_folded_body(body: &str) -> Option<u64> {
    let inner = body.strip_prefix(FOLD_PREFIX)?.strip_suffix(FOLD_SUFFIX)?;
    let mut chars = inner.chars();
    let tag = chars.next()?;
    let rest = chars.as_str();
    let sep_idx = rest.find(OPERAND_SEP)?;
    let (left, right) = rest.split_at(sep_idx);
    let right = &right[OPERAND_SEP.len_utf8()..];
    let left = parse_operand(left)?;
    let right = parse_operand(right)?;
    match tag {
        TAG_ADD => Some(left.checked_add(right)?),
        TAG_SUB => left.checked_sub(right),
        _ => None,
    }
}

/// `true` if `body` is a well-formed L9 folded-constant marker.
#[must_use]
pub fn is_folded_body(body: &str) -> bool {
    evaluate_folded_body(body).is_some()
}

/// Apply L9: replace every eligible bare-decimal-integer `Word` token
/// with a folded-constant marker. Returns the transformed stream,
/// same length and token order as the input.
///
/// Empty input is returned unchanged. Tokens that are not eligible
/// (see module MVP-scope docs) pass through untouched.
#[must_use]
pub fn fold_constants(tokens: Vec<Token>, epoch: u64) -> Vec<Token> {
    let mut rng = XorShift64::from_epoch(epoch);
    tokens
        .into_iter()
        .map(|tok| match &tok {
            Token::Word(s) => match parse_foldable_literal(s) {
                Some(n) => Token::word(fold_marker(n, &mut rng)),
                None => tok,
            },
            Token::Whitespace(_) => tok,
        })
        .collect()
}

/// Apply L9 inverse: replace every folded-constant marker `Word`
/// token with the plain-decimal `Word` token holding its original
/// value. Tokens without a recognizable marker are unchanged. Safe
/// to call on a stream that never went through [`fold_constants`].
#[must_use]
pub fn unfold_constants(tokens: Vec<Token>) -> Vec<Token> {
    tokens
        .into_iter()
        .map(|tok| match &tok {
            Token::Word(s) => match evaluate_folded_body(s) {
                Some(n) => Token::word(n.to_string()),
                None => tok,
            },
            Token::Whitespace(_) => tok,
        })
        .collect()
}

/// `true` if `tokens` contains at least one folded-constant marker.
#[must_use]
pub fn has_any_folded(tokens: &[Token]) -> bool {
    tokens
        .iter()
        .any(|t| matches!(t, Token::Word(b) if is_folded_body(b)))
}

#[cfg(test)]
mod tests {
    use super::{
        add_marker, fold_constants, has_any_folded, is_folded_body, sub_marker,
        unfold_constants, MAX_FOLD_VALUE, MIN_FOLD_VALUE,
    };
    use crate::python_tokenizer::tokenize;
    use crate::tokens::Token;

    #[test]
    fn add_marker_round_trips() {
        assert!(is_folded_body(&add_marker(7, 15)));
    }

    #[test]
    fn sub_marker_round_trips() {
        assert!(is_folded_body(&sub_marker(30, 8)));
    }

    #[test]
    fn is_folded_body_rejects_nonmatches() {
        for bad in [
            "",
            "foo",
            "__bbnfold__",
            "__bbnfoldz1x2__",
            "__bbnfolda1__",
            "__bbnfolda1x__",
            "__bbnfoldax2__",
            "bbnfolda1x2__",
            "__bbnfolda1x2",
            "__bbndecoy0__",
            "__bbnpos0__",
            "22",
        ] {
            assert!(!is_folded_body(bad), "should reject {bad:?}");
        }
    }

    #[test]
    fn empty_input_returns_unchanged() {
        assert!(fold_constants(Vec::new(), 0).is_empty());
        assert!(unfold_constants(Vec::new()).is_empty());
    }

    #[test]
    fn bare_literal_gets_folded() {
        let toks = vec![
            Token::word("port"),
            Token::word("="),
            Token::word("22"),
        ];
        let folded = fold_constants(toks, 0);
        assert!(has_any_folded(&folded));
        // The literal token itself must no longer be plain "22".
        assert!(!folded.iter().any(|t| matches!(t, Token::Word(s) if s == "22")));
    }

    #[test]
    fn fold_then_unfold_recovers_original_value() {
        for epoch in 0u64..20 {
            let toks = vec![Token::word("22")];
            let folded = fold_constants(toks.clone(), epoch);
            let recovered = unfold_constants(folded);
            assert_eq!(recovered, toks, "round-trip failed at epoch={epoch}");
        }
    }

    #[test]
    fn full_source_round_trips_through_tokenizer() {
        let src = "port = 22\ntimeout = 30\nx = 1\ny = 0\nz = 999999999\n";
        let toks = tokenize(src);
        for epoch in 0u64..8 {
            let folded = fold_constants(toks.clone(), epoch);
            let recovered = unfold_constants(folded);
            assert_eq!(recovered, toks, "round-trip failed at epoch={epoch}");
        }
    }

    #[test]
    fn zero_and_one_are_never_folded() {
        let toks = vec![Token::word("0"), Token::word("1")];
        let folded = fold_constants(toks.clone(), 5);
        assert_eq!(folded, toks, "0 and 1 must pass through unfolded");
    }

    #[test]
    fn value_above_max_is_not_folded() {
        let huge = (MAX_FOLD_VALUE + 1).to_string();
        let toks = vec![Token::word(huge.clone())];
        let folded = fold_constants(toks.clone(), 0);
        assert_eq!(folded, toks);
    }

    #[test]
    fn min_fold_value_is_folded_max_fold_value_is_folded() {
        for n in [MIN_FOLD_VALUE, MAX_FOLD_VALUE] {
            let toks = vec![Token::word(n.to_string())];
            let folded = fold_constants(toks, 7);
            assert!(has_any_folded(&folded), "n={n} should fold");
        }
    }

    #[test]
    fn leading_zero_literal_is_left_untouched() {
        // "007" is not valid Python, but the tokenizer doesn't
        // validate syntax (MVP_LIMITATIONS #6); folding it would lose
        // the leading zeros on unfold (n.to_string() != "007"), so it
        // must be skipped rather than corrupted.
        let toks = vec![Token::word("007")];
        let folded = fold_constants(toks.clone(), 0);
        assert_eq!(folded, toks);
    }

    #[test]
    fn non_numeric_word_is_never_folded() {
        let toks = vec![Token::word("hello"), Token::word("x22"), Token::word("22x")];
        let folded = fold_constants(toks.clone(), 0);
        assert_eq!(folded, toks);
    }

    #[test]
    fn negative_looking_word_is_never_folded() {
        // "-22" is one opaque Word per the tokenizer's operator-
        // adjacency limitation; the leading '-' fails the pure-digit
        // check so it is left alone.
        let toks = vec![Token::word("-22")];
        let folded = fold_constants(toks.clone(), 0);
        assert_eq!(folded, toks);
    }

    #[test]
    fn float_looking_word_is_never_folded() {
        let toks = vec![Token::word("3.14")];
        let folded = fold_constants(toks.clone(), 0);
        assert_eq!(folded, toks);
    }

    #[test]
    fn folding_is_deterministic_per_epoch() {
        let toks = vec![Token::word("42")];
        let a = fold_constants(toks.clone(), 3);
        let b = fold_constants(toks, 3);
        assert_eq!(a, b);
    }

    #[test]
    fn same_value_gets_varied_decompositions_across_occurrences() {
        // Frequency-analysis resistance: the same literal appearing
        // twice in one file must not fold to the same marker text
        // both times (the whole point is to not leave a fixed
        // fingerprint for a repeated constant).
        let toks = vec![Token::word("500"), Token::word("500"), Token::word("500")];
        let folded = fold_constants(toks, 11);
        let bodies: Vec<&str> = folded
            .iter()
            .map(|t| match t {
                Token::Word(s) => s.as_str(),
                Token::Whitespace(_) => unreachable!(),
            })
            .collect();
        assert!(
            bodies[0] != bodies[1] || bodies[1] != bodies[2],
            "expected at least one differing decomposition, got {bodies:?}"
        );
    }

    #[test]
    fn different_epochs_produce_different_markers() {
        let toks = vec![Token::word("777")];
        let a = fold_constants(toks.clone(), 1);
        let b = fold_constants(toks, 2);
        assert_ne!(a, b);
    }

    #[test]
    fn whitespace_tokens_pass_through_unfold() {
        use crate::tokens::WhitespaceKind;
        let toks = vec![Token::whitespace(WhitespaceKind::Space)];
        assert_eq!(unfold_constants(toks.clone()), toks);
    }

    #[test]
    fn unfold_is_a_no_op_on_a_stream_never_folded() {
        let src = "x = 1\ny = 2\n# comment 22\n\"literal 22 in string\"\n";
        let toks = tokenize(src);
        assert_eq!(unfold_constants(toks.clone()), toks);
    }

    #[test]
    fn string_and_comment_literals_are_never_touched() {
        // Numeric-looking substrings inside a string or comment are
        // part of a larger opaque Word (the tokenizer's string/
        // comment state machine swallows the whole literal, quotes
        // or hash included), so they never match the pure-digit
        // check and must survive fold+unfold byte-for-byte.
        let src = "x = \"port 22\"\n# retries: 3\ny = 22\n";
        let toks = tokenize(src);
        let folded = fold_constants(toks.clone(), 4);
        let recovered = unfold_constants(folded.clone());
        assert_eq!(recovered, toks);
        // But the bare "22" assigned to y (surrounded by whitespace)
        // must have actually folded, proving the string/comment ones
        // were skipped rather than the whole test being vacuous.
        assert!(has_any_folded(&folded));
        let string_word_untouched = folded
            .iter()
            .any(|t| matches!(t, Token::Word(s) if s == "\"port 22\""));
        let comment_word_untouched = folded
            .iter()
            .any(|t| matches!(t, Token::Word(s) if s == "# retries: 3"));
        assert!(string_word_untouched, "string literal must be untouched");
        assert!(comment_word_untouched, "comment must be untouched");
    }

    #[test]
    fn evaluate_folded_body_rejects_overflowing_add() {
        // Hand-crafted marker whose operands overflow u64 on add:
        // checked_add must return None (is_folded_body -> false)
        // rather than panicking.
        let huge = u64::MAX.to_string();
        let marker = format!("__bbnfolda{huge}x{huge}__");
        assert!(!is_folded_body(&marker));
    }

    #[test]
    fn evaluate_folded_body_rejects_underflowing_sub() {
        let marker = "__bbnfolds1x5__"; // 1 - 5 underflows
        assert!(!is_folded_body(marker));
    }
}
