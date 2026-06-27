//! Language-agnostic dynamic identifier scramble — Token-stream transform.
//!
//! # What this defeats
//!
//! Every unique whitespace-delimited token in the source gets its own
//! per-epoch scrambled compound, derived from the per-host secret.  No
//! pre-baked keyword list is needed; the mapping is built from the
//! file's own content.
//!
//! Compared to the old Python-specific L2/L2b passes, this has three
//! advantages:
//!
//! 1. **Language-agnostic.** Works on any source that the structural
//!    tokenizer (L3) can round-trip; no Python keyword or operator
//!    lists to maintain.
//! 2. **Context-aware.** `code()` and `code""` both rely on `code`
//!    but appear as different whitespace-delimited tokens (`code()`
//!    vs `code""`), so each gets a distinct compound.  An attacker
//!    cannot collapse them.
//! 3. **Multi-alias.** Each token maps to [`ALIAS_COUNT`] independent
//!    compounds (one per virtual epoch).  At scramble time the pass
//!    cycles through aliases across occurrences of the same token,
//!    defeating frequency analysis: a token that appears 100 times
//!    does not produce 100 identical compounds in the output.
//!
//! # What this does NOT defeat
//!
//! - An attacker who knows the full token list AND the per-host secret
//!   can reconstruct every alias.  The token list is stored in the
//!   scrambled file's header (required for unscrambling without the
//!   original source); protection comes entirely from the secret.
//!
//! # Composition
//!
//! This pass runs at the `Token` level, BEFORE layer 3
//! (whitespace-as-words).  Order at scramble time:
//!
//! 1. Tokenize source → `Vec<Token>`.
//! 2. Collect unique tokens → ask daemon for compounds.
//! 3. [`scramble_identifiers`] (this module) — in-place.
//! 4. `scrambler::scramble` — whitespace markers → compounds.
//!
//! Inverse at unscramble time (read header for token list, then
//! same daemon request to rebuild aliases):
//!
//! 1. `unscrambler::unscramble_to_tokens`.
//! 2. [`unscramble_identifiers`] (this module) — in-place.
//! 3. `unscrambler::tokens_to_source`.

use std::collections::{BTreeSet, HashMap};

use crate::tokens::Token;

/// Number of independent per-token aliases produced per epoch.
///
/// The daemon builds `ALIAS_COUNT` separate compound mappings for each
/// requested token (using virtual epochs `epoch * ALIAS_COUNT + i`).
/// At scramble time the pass cycles through aliases by occurrence index
/// so repeated tokens produce varied compounds, defeating
/// frequency-count inference.
///
/// # Status
///
/// `ALIAS_COUNT` is the legacy fixed-count invariant that applies to
/// every scrambled file at file-format versions 0 and 1.  Files emitted
/// at version 2 and later size their alias matrix per-epoch via
/// [`alias_count_for_epoch`]; see that function's docs for the
/// motivation.  Production call sites that hard-code "3" are now
/// confined to back-compat code paths gated on
/// `version < ALIAS_COUNT_VARIABLE_FROM_VERSION`; new call sites
/// should derive the count via [`alias_count_for_epoch`].
pub const ALIAS_COUNT: usize = 3;

/// Minimum alias count produced by [`alias_count_for_epoch`] for
/// post-legacy file-format versions.
///
/// Lower bound chosen so every token always has at least two aliases —
/// a single alias would degenerate to the deterministic-mapping shape
/// that frequency analysis attacks.
pub const MIN_ALIAS_COUNT: usize = 2;

/// Maximum alias count produced by [`alias_count_for_epoch`] for
/// post-legacy file-format versions.
///
/// Upper bound chosen so the daemon's per-request work stays bounded:
/// at `MAX_ALIAS_COUNT = 5`, a `GetTokenMapping` round-trip rebuilds
/// at most 5 × 2 = 10 permutations (identifier + honey per virtual
/// epoch).  Above this the cache footprint grows linearly and rotation
/// blast radius gets ugly without commensurate defender benefit.
pub const MAX_ALIAS_COUNT: usize = 5;

/// File-format version at which the alias count became a per-epoch
/// deterministic function instead of a fixed constant.
///
/// Files with `version < ALIAS_COUNT_VARIABLE_FROM_VERSION` use
/// [`ALIAS_COUNT`] verbatim (legacy invariant); files at or above
/// this version size their matrix via [`alias_count_for_epoch`].
///
/// The cutoff is named at the call site rather than embedded inline
/// so a future format-bump that re-tunes the alias range (e.g. raising
/// `MAX_ALIAS_COUNT`) lands in one place.
pub const ALIAS_COUNT_VARIABLE_FROM_VERSION: u32 = 2;

/// Deterministic per-epoch alias count for a given file-format
/// version.
///
/// # What this defeats
///
/// An attacker who counts compound occurrences in a scrambled body
/// and assumes the alias cycle has a fixed length cannot solve the
/// recovered cycle without the version+epoch pair.  Without the
/// alias count, a single L2 frequency-analysis pass cannot align
/// compound runs to original tokens.  This is a strict improvement
/// over the legacy invariant `ALIAS_COUNT = 3`, which made the
/// cycle length public and offered nothing to a counter-analysis
/// adversary.
///
/// # Mechanism
///
/// For `format_version < ALIAS_COUNT_VARIABLE_FROM_VERSION` returns
/// [`ALIAS_COUNT`] — the legacy fixed value — so files emitted under
/// older format versions unscramble correctly.
///
/// For `format_version >= ALIAS_COUNT_VARIABLE_FROM_VERSION` returns
/// a value in `MIN_ALIAS_COUNT ..= MAX_ALIAS_COUNT` derived from
/// `epoch` via a public deterministic mix (golden-ratio
/// multiplicative hash + xor).  The mix is NOT secret-derived: the
/// alias count is observable in the daemon's response and so is
/// already public; mixing in HKDF would buy nothing.
///
/// # Determinism contract
///
/// `alias_count_for_epoch(v, e) == alias_count_for_epoch(v, e)` for
/// every `(v, e)` pair — the function is total, side-effect-free,
/// and consults nothing outside its arguments.  Both ends of a
/// scramble/unscramble round-trip MUST compute the same value or
/// the daemon's alias matrix will not align with the body bytes.
///
/// # Distribution
///
/// The mix is intended to be uniform in the
/// `MIN_ALIAS_COUNT ..= MAX_ALIAS_COUNT` range across consecutive
/// epochs; the dedicated test
/// `alias_count_for_epoch_is_uniform_over_a_large_window` asserts
/// every value in the range appears at least once across the first
/// 1024 epochs.
#[must_use]
pub fn alias_count_for_epoch(format_version: u32, epoch: u64) -> usize {
    if format_version < ALIAS_COUNT_VARIABLE_FROM_VERSION {
        return ALIAS_COUNT;
    }
    // Public deterministic mix.  The constants are arbitrary
    // well-known primes / golden-ratio words; they do not depend on
    // the per-host secret.  Keeping the mix public (and therefore
    // trivially recoverable from a published scrambled file) is fine
    // because the alias count is already observable in the daemon's
    // wire response.
    const MIX_MUL: u64 = 0x9E37_79B9_7F4A_7C15;
    const MIX_XOR: u64 = 0xDEAD_BEEF_CAFE_BABE;
    let mixed = epoch.wrapping_mul(MIX_MUL) ^ MIX_XOR;
    let range = (MAX_ALIAS_COUNT - MIN_ALIAS_COUNT + 1) as u64;
    // High 32 bits feed the modulo — discards the predictable low
    // bits that LCG-style mixes leak.
    let bucket = (mixed >> 32) % range;
    MIN_ALIAS_COUNT + bucket as usize
}

/// Per-file identifier mapping built from daemon-supplied aliases.
///
/// `sorted_tokens` and `epoch` are the two pieces the scrambled-file
/// header stores so the unscrambler can ask the daemon for the same
/// mapping without the original source.
pub struct IdentifierMapping {
    /// Sorted unique tokens, in the same order supplied to the daemon.
    pub sorted_tokens: Vec<String>,
    /// Epoch the compounds were derived for.
    pub epoch: u64,
    /// Original token → `[alias_0, alias_1, ..., alias_{ALIAS_COUNT-1}]`.
    forward: HashMap<String, Vec<String>>,
    /// Compound → original token (covers every alias for every token).
    reverse: HashMap<String, String>,
}

impl IdentifierMapping {
    /// Build the mapping from a `(sorted_tokens, epoch, aliases)` triple
    /// returned by the daemon's `GetTokenMapping` response.
    ///
    /// `aliases[token_idx]` must be a `Vec` of exactly [`ALIAS_COUNT`]
    /// compounds.  All compounds across all tokens and all aliases must
    /// be unique; duplicate compounds indicate a collision in the
    /// per-epoch derivation (astronomically rare with the v2 baseline
    /// wordlist; rotate the epoch if it ever occurs).
    ///
    /// # Errors
    ///
    /// - `Error::Scramble` if any compound appears more than once across
    ///   the full `aliases` matrix.
    pub fn from_tokens_and_aliases(
        sorted_tokens: Vec<String>,
        epoch: u64,
        aliases: Vec<Vec<String>>,
    ) -> crate::errors::Result<Self> {
        let mut forward = HashMap::with_capacity(sorted_tokens.len());
        let mut reverse =
            HashMap::with_capacity(sorted_tokens.len() * ALIAS_COUNT);
        for (token, token_aliases) in sorted_tokens.iter().zip(aliases.iter()) {
            for compound in token_aliases {
                if reverse.insert(compound.clone(), token.clone()).is_some() {
                    return Err(crate::errors::Error::Scramble(format!(
                        "identifier-mapping collision: compound {compound:?} \
                         assigned to more than one token; rotate the epoch",
                    )));
                }
            }
            forward.insert(token.clone(), token_aliases.clone());
        }
        Ok(Self { sorted_tokens, epoch, forward, reverse })
    }

    /// Return the compound for `token` at the given occurrence index.
    ///
    /// Picks alias `occurrence % ALIAS_COUNT`.  Returns `None` if
    /// `token` was not in the original `sorted_tokens` list (i.e. was
    /// not in the file when the mapping was built).
    #[must_use]
    pub fn scramble(&self, token: &str, occurrence: usize) -> Option<&str> {
        let aliases = self.forward.get(token)?;
        let alias_idx = occurrence % aliases.len();
        aliases.get(alias_idx).map(String::as_str)
    }

    /// Return the original token for `compound`, or `None` if the
    /// compound is not in this mapping.
    #[must_use]
    pub fn unscramble(&self, compound: &str) -> Option<&str> {
        self.reverse.get(compound).map(String::as_str)
    }
}

/// Collect every unique `Token::Word` body from the stream, sorted
/// deterministically.
///
/// The sorted order is the canonical order supplied to the daemon and
/// embedded in the scrambled-file header; both ends must use the same
/// ordering to derive consistent compounds.
#[must_use]
pub fn collect_unique_tokens(tokens: &[Token]) -> Vec<String> {
    let mut set = BTreeSet::new();
    for token in tokens {
        if let Token::Word(body) = token {
            set.insert(body.clone());
        }
    }
    set.into_iter().collect()
}

/// Replace every `Token::Word` body with its per-alias compound.
///
/// Cycles through aliases by per-token occurrence count so repeated
/// tokens produce varied compounds.  Whitespace markers are untouched.
///
/// Tokens absent from `mapping` (not in the file when the mapping was
/// built, which cannot happen in a well-formed call) are left verbatim.
pub fn scramble_identifiers(tokens: &mut [Token], mapping: &IdentifierMapping) {
    let mut counters: HashMap<String, usize> = HashMap::new();
    for token in tokens.iter_mut() {
        if let Token::Word(body) = token {
            let original = body.clone();
            let occurrence = counters.entry(original.clone()).or_insert(0);
            let idx = *occurrence;
            *occurrence += 1;
            if let Some(compound) = mapping.scramble(&original, idx) {
                *body = compound.to_string();
            }
        }
    }
}

/// Replace every `Token::Word` body with its original token.
///
/// Looks each compound up in the reverse map.  Compounds not in the
/// map (i.e. not produced by [`scramble_identifiers`]) are left
/// verbatim; this handles leftover whitespace-compound fragments that
/// the L3 unscrambler already consumed, as well as any token the
/// mapping does not cover.
///
/// Whitespace markers are untouched.
pub fn unscramble_identifiers(
    tokens: &mut [Token],
    mapping: &IdentifierMapping,
) {
    for token in tokens.iter_mut() {
        if let Token::Word(body) = token {
            if let Some(original) = mapping.unscramble(body) {
                *body = original.to_string();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        alias_count_for_epoch, collect_unique_tokens, scramble_identifiers,
        unscramble_identifiers, IdentifierMapping, ALIAS_COUNT,
        ALIAS_COUNT_VARIABLE_FROM_VERSION, MAX_ALIAS_COUNT, MIN_ALIAS_COUNT,
    };
    use crate::tokens::{Token, WhitespaceKind};

    fn make_mapping(tokens: &[&str], epoch: u64) -> IdentifierMapping {
        let sorted_tokens: Vec<String> =
            tokens.iter().map(|s| (*s).to_string()).collect();
        // Synthesize unique compounds: "<token>_e<epoch>_a<alias>"
        let aliases: Vec<Vec<String>> = sorted_tokens
            .iter()
            .map(|t| {
                (0..ALIAS_COUNT)
                    .map(|a| format!("{t}_e{epoch}_a{a}"))
                    .collect()
            })
            .collect();
        IdentifierMapping::from_tokens_and_aliases(
            sorted_tokens,
            epoch,
            aliases,
        )
        .expect("synthetic mapping must not collide")
    }

    #[test]
    fn collect_unique_tokens_returns_sorted_deduped_words() {
        let tokens = vec![
            Token::word("def"),
            Token::whitespace(WhitespaceKind::Space),
            Token::word("foo"),
            Token::whitespace(WhitespaceKind::Newline),
            Token::word("def"),
            Token::word("bar"),
        ];
        let unique = collect_unique_tokens(&tokens);
        assert_eq!(unique, vec!["bar", "def", "foo"]);
    }

    #[test]
    fn collect_unique_tokens_empty_stream() {
        assert!(collect_unique_tokens(&[]).is_empty());
    }

    #[test]
    fn collect_unique_tokens_whitespace_only_stream() {
        let tokens = vec![
            Token::whitespace(WhitespaceKind::Newline),
            Token::whitespace(WhitespaceKind::Space),
        ];
        assert!(collect_unique_tokens(&tokens).is_empty());
    }

    #[test]
    fn scramble_then_unscramble_round_trips_every_token() {
        let m = make_mapping(&["def", "foo", "return", "x"], 0);
        let mut tokens = vec![
            Token::word("def"),
            Token::whitespace(WhitespaceKind::Space),
            Token::word("foo"),
            Token::whitespace(WhitespaceKind::Newline),
            Token::word("return"),
            Token::whitespace(WhitespaceKind::Space),
            Token::word("x"),
        ];
        let original = tokens.clone();
        scramble_identifiers(&mut tokens, &m);
        // After scramble, no original token body remains.
        for (tok, orig) in tokens.iter().zip(original.iter()) {
            if let Token::Word(body) = tok {
                if let Token::Word(ob) = orig {
                    assert_ne!(body, ob, "token {ob:?} was not scrambled");
                }
            }
        }
        unscramble_identifiers(&mut tokens, &m);
        assert_eq!(tokens, original, "round-trip failed");
    }

    #[test]
    fn whitespace_markers_are_never_touched() {
        let m = make_mapping(&["def"], 0);
        let mut tokens = vec![
            Token::whitespace(WhitespaceKind::IndentOpen),
            Token::word("def"),
            Token::whitespace(WhitespaceKind::Newline),
        ];
        scramble_identifiers(&mut tokens, &m);
        assert_eq!(tokens[0], Token::whitespace(WhitespaceKind::IndentOpen));
        assert_eq!(tokens[2], Token::whitespace(WhitespaceKind::Newline));
    }

    #[test]
    fn aliases_cycle_across_occurrences() {
        let m = make_mapping(&["x"], 0);
        let mut tokens: Vec<Token> =
            (0..ALIAS_COUNT * 2).map(|_| Token::word("x")).collect();
        scramble_identifiers(&mut tokens, &m);
        // First ALIAS_COUNT should cover all aliases; second set repeats.
        let first_cycle: Vec<_> =
            tokens[..ALIAS_COUNT].iter().map(|t| t.clone()).collect();
        let second_cycle: Vec<_> =
            tokens[ALIAS_COUNT..2 * ALIAS_COUNT].iter().cloned().collect();
        assert_eq!(
            first_cycle, second_cycle,
            "aliases should repeat after ALIAS_COUNT occurrences",
        );
        // All first-cycle compounds must be distinct.
        let mut bodies: Vec<&str> = first_cycle
            .iter()
            .map(|t| if let Token::Word(b) = t { b.as_str() } else { "" })
            .collect();
        bodies.sort_unstable();
        let before = bodies.len();
        bodies.dedup();
        assert_eq!(bodies.len(), before, "first-cycle aliases not distinct");
    }

    #[test]
    fn duplicate_compound_in_aliases_errors() {
        let sorted_tokens = vec!["a".to_string(), "b".to_string()];
        // Force a collision: both tokens get the same compound for alias 0.
        let aliases = vec![
            vec!["SAME".to_string(), "unique_a1".to_string(), "unique_a2".to_string()],
            vec!["SAME".to_string(), "unique_b1".to_string(), "unique_b2".to_string()],
        ];
        let err = IdentifierMapping::from_tokens_and_aliases(
            sorted_tokens,
            0,
            aliases,
        );
        assert!(err.is_err(), "collision must be rejected");
    }

    #[test]
    fn unscramble_leaves_unknown_compound_verbatim() {
        let m = make_mapping(&["def"], 0);
        let mut tokens = vec![Token::word("totally_unknown_compound_xyz")];
        unscramble_identifiers(&mut tokens, &m);
        assert_eq!(tokens[0], Token::word("totally_unknown_compound_xyz"));
    }

    #[test]
    fn collect_unique_tokens_returns_btreeset_sorted_order() {
        let tokens = vec![
            Token::word("zoo"),
            Token::word("apple"),
            Token::word("mango"),
        ];
        let unique = collect_unique_tokens(&tokens);
        assert_eq!(unique, vec!["apple", "mango", "zoo"]);
    }

    // ----- alias_count_for_epoch -----

    #[test]
    fn alias_count_for_legacy_format_returns_constant() {
        // Versions 0 and 1 (every file shipped before the bump)
        // MUST return ALIAS_COUNT verbatim so existing scrambled
        // files unscramble correctly under the new builder.
        for v in 0..ALIAS_COUNT_VARIABLE_FROM_VERSION {
            for epoch in [0u64, 1, 42, 12_345, u64::MAX] {
                assert_eq!(
                    alias_count_for_epoch(v, epoch),
                    ALIAS_COUNT,
                    "legacy version {v} epoch {epoch} must return ALIAS_COUNT",
                );
            }
        }
    }

    #[test]
    fn alias_count_for_v2_is_always_in_range() {
        // The post-legacy mix must never escape the documented
        // bounds; a function that returned 6 or 1 would silently
        // mis-size the alias matrix downstream.  Exhaustive over a
        // 4096-epoch window — enough to catch any off-by-one in the
        // modulo step.
        for epoch in 0u64..4096 {
            let n = alias_count_for_epoch(
                ALIAS_COUNT_VARIABLE_FROM_VERSION,
                epoch,
            );
            assert!(
                (MIN_ALIAS_COUNT..=MAX_ALIAS_COUNT).contains(&n),
                "alias_count_for_epoch(v2, {epoch}) = {n} out of range \
                 [{MIN_ALIAS_COUNT}, {MAX_ALIAS_COUNT}]",
            );
        }
    }

    #[test]
    fn alias_count_for_epoch_is_deterministic() {
        // Same input → same output, every time.  The function is
        // total and side-effect-free.
        for v in [0u32, 1, 2, 3, 7] {
            for epoch in [0u64, 1, 2, 99, 1234, u64::MAX] {
                let a = alias_count_for_epoch(v, epoch);
                let b = alias_count_for_epoch(v, epoch);
                assert_eq!(a, b);
            }
        }
    }

    #[test]
    fn alias_count_for_epoch_is_uniform_over_a_large_window() {
        // Every value in [MIN_ALIAS_COUNT, MAX_ALIAS_COUNT] must
        // appear at least once across the first 1024 epochs.  This
        // guards against a pathological mix that locked to one
        // bucket — defeating the whole point of varying the count.
        use std::collections::BTreeSet;
        let mut seen: BTreeSet<usize> = BTreeSet::new();
        for epoch in 0u64..1024 {
            seen.insert(alias_count_for_epoch(
                ALIAS_COUNT_VARIABLE_FROM_VERSION,
                epoch,
            ));
        }
        let expected: BTreeSet<usize> =
            (MIN_ALIAS_COUNT..=MAX_ALIAS_COUNT).collect();
        assert_eq!(
            seen, expected,
            "alias-count mix should cover every value in \
             [{MIN_ALIAS_COUNT}, {MAX_ALIAS_COUNT}] across 1024 epochs",
        );
    }

    #[test]
    fn alias_count_for_epoch_actually_varies_across_consecutive_epochs() {
        // A function that returned a constant for v2+ would silently
        // re-introduce the legacy invariant.  This test fails fast
        // if a future edit pins the mix to one value.
        let v = ALIAS_COUNT_VARIABLE_FROM_VERSION;
        let first = alias_count_for_epoch(v, 0);
        let varies = (1u64..1024)
            .any(|e| alias_count_for_epoch(v, e) != first);
        assert!(
            varies,
            "alias_count_for_epoch must vary across consecutive \
             epochs for v >= {ALIAS_COUNT_VARIABLE_FROM_VERSION}",
        );
    }

    #[test]
    fn alias_count_for_future_versions_uses_the_v2_mix() {
        // Any version >= ALIAS_COUNT_VARIABLE_FROM_VERSION takes the
        // post-legacy path.  This guards against a regression where a
        // hypothetical version-3 bump implicitly fell back to the
        // legacy path because the cutoff was hard-coded as `== 2`.
        let v2 = alias_count_for_epoch(
            ALIAS_COUNT_VARIABLE_FROM_VERSION,
            42,
        );
        let v3 = alias_count_for_epoch(
            ALIAS_COUNT_VARIABLE_FROM_VERSION + 1,
            42,
        );
        let v7 = alias_count_for_epoch(
            ALIAS_COUNT_VARIABLE_FROM_VERSION + 5,
            42,
        );
        assert_eq!(v2, v3);
        assert_eq!(v2, v7);
    }

    #[test]
    fn alias_count_constants_satisfy_invariants() {
        // ALIAS_COUNT must lie inside the post-legacy range so the
        // builder's PermutationCache sizing logic (which keys on
        // MAX_ALIAS_COUNT * 2 slots) covers the legacy case without
        // extra plumbing.
        assert!(
            (MIN_ALIAS_COUNT..=MAX_ALIAS_COUNT).contains(&ALIAS_COUNT),
            "legacy ALIAS_COUNT ({ALIAS_COUNT}) must lie inside the \
             post-legacy range [{MIN_ALIAS_COUNT}, {MAX_ALIAS_COUNT}]",
        );
        assert!(MIN_ALIAS_COUNT >= 2);
        assert!(MAX_ALIAS_COUNT <= 8);
        assert!(MIN_ALIAS_COUNT < MAX_ALIAS_COUNT);
    }
}
