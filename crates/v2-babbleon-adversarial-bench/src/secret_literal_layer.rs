//! Experimental layer-7 secret-literal substitution — bench-only.
//!
//! # What this defeats
//!
//! The dominant finding from the 2026-06-21 bench run: string
//! literals containing program secrets survive L2 (keyword
//! scramble) and L3 (whitespace-as-words) verbatim, and the
//! adversary recovers them by literal search.  See
//! `docs/v2/string-literal-leak.md` for the full discussion.
//!
//! This module implements a **bench-only prototype** of the
//! proposed layer-7 mechanism: the operator marks a literal as
//! secret by wrapping it in a sentinel function call
//! `secret("...")`, and the preprocessor (or, here, the bench)
//! recognises the wrapper and substitutes the literal body with
//! a per-epoch HKDF-derived wordlist compound.  The scrambled
//! source remains syntactically valid Python — the wrapper call
//! and its surrounding code are untouched; only the string body
//! between the quotes changes.
//!
//! # Mechanism
//!
//! For each `secret("BODY")` occurrence in the source:
//!
//! 1. Derive `compound = wordlist_compound(secret, epoch,
//!    purpose=b"v2-bench-secret-literal:" + BODY, n_words=4)`.
//!    The literal body participates in the HKDF info parameter,
//!    so different bodies derive different compounds.  Same body
//!    + same secret + same epoch → same compound (deterministic).
//! 2. Replace the body with the compound.  The surrounding
//!    `secret("` and `")` tokens are unchanged.
//!
//! Reverse: build the same compound → body mapping during the
//! forward pass, persist it (here: returned to the caller as a
//! `HashMap`), and substitute compounds back to bodies on
//! unscramble.
//!
//! # Threat model boundaries
//!
//! - **Defeats:** literal-search recovery of operator-marked
//!   secret strings.  An adversary without the per-host secret
//!   cannot derive the compound and therefore cannot reverse the
//!   substitution.
//! - **Does NOT defeat:** literal recovery from *unmarked*
//!   literals (operator forgot to wrap).  The bench's
//!   `computed-secret` cell shows another failure mode this
//!   layer does NOT address: secrets that are reconstructed at
//!   runtime from per-character `chr()` calls survive layer 7
//!   because they are not string literals in the first place,
//!   and an adversary with a python interpreter trivially
//!   evaluates the reconstruction.  Layer 7 is necessary but not
//!   sufficient.
//!
//! # Bench-only scope
//!
//! This module is in the bench crate, not the production
//! preprocessor crate.  Rationale:
//!
//! - **Iteration speed.**  The preprocessor's `Token` IR and
//!   wordlist plumbing changes need operator review; a bench-side
//!   prototype lets us measure crack-fraction first and inform
//!   the production design.
//! - **No production risk.**  The bench can drive the prototype
//!   freely without affecting `v2-babbleon-preprocessor` /
//!   `v2-babbleon-daemon` / `v2-babbleon` CLI.
//! - **Compositional ordering.**  Layer 7 here runs *before*
//!   layer 2 and layer 3 — it operates on source text, not on
//!   the `Token` IR, so the L2/L3 passes downstream do not need
//!   to know about secret literals.
//!
//! When the design moves to production, this module becomes the
//! reference implementation the preprocessor crate ports against.

use std::collections::HashMap;

use babbleon_core_v2::key_derivation::derive_subkey;
use babbleon_core_v2::per_host_secret::PerHostSecret;
use babbleon_core_v2::wordlist::Wordlist;

use crate::errors::{Error, Result};

/// HKDF purpose label.  Bench-distinct from the production
/// preprocessor labels (`v2-keyword-mapping`, `v2-whitespace-mapping`,
/// `v2-identifier-mapping`, ...) so a bench-derived compound never
/// collides with a production one even under the same secret +
/// epoch.
const PURPOSE_PREFIX: &[u8] = b"v2-bench-secret-literal:";

/// Number of wordlist words concatenated to form one compound.
/// Same default as the production whitespace wordlist
/// (`WHITESPACE_COMPOUND_COUNT_WIRE = 5` minus one — chosen here as
/// 4 because operator-marked literal bodies are typically shorter
/// than indent-block markers and 4 words gives a comparable
/// pre-image space).
pub const COMPOUND_WORD_COUNT: usize = 4;

/// Substitute every `secret("BODY")` occurrence in `source` with
/// `secret("<compound>")` where the compound is derived from
/// `(secret, epoch, BODY)` via HKDF over the bench-only purpose
/// label.
///
/// Returns the modified source and a mapping `compound → BODY`
/// the caller can use to reverse the substitution.
///
/// # Errors
///
/// - `Error::Scramble` if HKDF derivation or wordlist indexing
///   fails (effectively impossible for `COMPOUND_WORD_COUNT * 4`
///   bytes of HKDF output; documented as a defensive check).
pub fn scramble_secret_literals(
    source: &str,
    secret: &PerHostSecret,
    epoch: u64,
) -> Result<(String, HashMap<String, String>)> {
    let wl = Wordlist::english_baseline();
    let mut mapping: HashMap<String, String> = HashMap::new();
    let mut out = String::with_capacity(source.len());
    for chunk in walk_secret_calls(source) {
        match chunk {
            Chunk::Passthrough(s) => out.push_str(s),
            Chunk::SecretCall { prefix, body, suffix } => {
                let compound = derive_compound(secret, epoch, body, wl)?;
                mapping
                    .insert(compound.clone(), body.to_string());
                out.push_str(prefix);
                out.push_str(&compound);
                out.push_str(suffix);
            }
        }
    }
    Ok((out, mapping))
}

/// Reverse [`scramble_secret_literals`].  Walks `scrambled` for
/// `secret("...")` calls; for each one whose body matches a
/// `mapping` key, substitutes the stored body back in.  Compounds
/// not in `mapping` are left unchanged — could be operator-error
/// (stale mapping) or a coincidental match against unmarked
/// `secret("...")` call sites.
#[must_use]
pub fn unscramble_secret_literals<S: std::hash::BuildHasher>(
    scrambled: &str,
    mapping: &HashMap<String, String, S>,
) -> String {
    let mut out = String::with_capacity(scrambled.len());
    for chunk in walk_secret_calls(scrambled) {
        match chunk {
            Chunk::Passthrough(s) => out.push_str(s),
            Chunk::SecretCall { prefix, body, suffix } => {
                out.push_str(prefix);
                if let Some(original) = mapping.get(body) {
                    out.push_str(original);
                } else {
                    out.push_str(body);
                }
                out.push_str(suffix);
            }
        }
    }
    out
}

/// Derive one compound for `(secret, epoch, body)`.
///
/// HKDF-Expand purpose = `PURPOSE_PREFIX || body.as_bytes()`.
/// Output is `COMPOUND_WORD_COUNT * 4` bytes, parsed as
/// little-endian `u32` slots; each slot indexes the wordlist
/// modulo `wl.len()`.  Returned compound is the concatenation
/// of the chosen wordlist entries (no separator).
fn derive_compound(
    secret: &PerHostSecret,
    epoch: u64,
    body: &str,
    wl: &Wordlist,
) -> Result<String> {
    let mut purpose = Vec::with_capacity(
        PURPOSE_PREFIX.len() + body.len(),
    );
    purpose.extend_from_slice(PURPOSE_PREFIX);
    purpose.extend_from_slice(body.as_bytes());

    let needed = COMPOUND_WORD_COUNT * 4;
    let bytes = derive_subkey(secret, epoch, &purpose, needed)
        .map_err(|e| Error::Scramble {
            message: format!("HKDF for secret-literal: {e}"),
        })?;

    let mut compound = String::new();
    let wl_len = wl.len();
    if wl_len == 0 {
        return Err(Error::Scramble {
            message: "wordlist is empty".into(),
        });
    }
    for i in 0..COMPOUND_WORD_COUNT {
        let off = i * 4;
        let raw = u32::from_le_bytes([
            bytes[off],
            bytes[off + 1],
            bytes[off + 2],
            bytes[off + 3],
        ]) as usize;
        let idx = raw % wl_len;
        let word = wl.get(idx).ok_or_else(|| Error::Scramble {
            message: format!("wordlist index {idx} out of range"),
        })?;
        compound.push_str(word);
    }
    Ok(compound)
}

/// One scan iteration's yield.
#[derive(Debug)]
enum Chunk<'a> {
    /// Verbatim source bytes (not inside a `secret()` call).
    Passthrough(&'a str),
    /// A `secret("...")` call.  `prefix` is `secret("`; `suffix`
    /// is `")`; `body` is the literal body between the quotes
    /// (without escape-character processing — bench-MVP supports
    /// only literal bodies that contain neither `"` nor `\`).
    SecretCall {
        prefix: &'a str,
        body: &'a str,
        suffix: &'a str,
    },
}

/// Stream `source` as alternating `Passthrough` / `SecretCall` chunks.
///
/// Scanner: walks byte-by-byte looking for the literal sequence
/// `secret("`; on match, finds the next closing `"`; on success,
/// yields a `SecretCall` with the spans of prefix / body / suffix
/// and continues past the closing `)`.  On any structural failure
/// (no closing quote, no closing paren), yields the partial input
/// as Passthrough so the caller is never starved of bytes.
fn walk_secret_calls(source: &str) -> Vec<Chunk<'_>> {
    let mut out = Vec::new();
    let bytes = source.as_bytes();
    let mut i = 0;
    let mut emit_passthrough_start = 0;
    while i < bytes.len() {
        if let Some(call_end) = try_match_secret_call(bytes, i) {
            // Emit the run of passthrough up to here.
            if i > emit_passthrough_start {
                out.push(Chunk::Passthrough(
                    &source[emit_passthrough_start..i],
                ));
            }
            // Parse the matched span into (prefix, body, suffix).
            // The fixed structure: `secret("BODY")` where BODY
            // contains no `"` or `\` (MVP limitation).  prefix
            // spans bytes [i .. i+len("secret(\"")]; body spans
            // [prefix_end .. closing_quote]; suffix spans
            // [closing_quote .. call_end].
            let prefix_end = i + SECRET_PREFIX.len();
            // Find closing quote.
            let closing_quote = source[prefix_end..call_end - 1]
                .find('"')
                .map(|off| prefix_end + off)
                .expect(
                    "try_match_secret_call guarantees a closing quote",
                );
            out.push(Chunk::SecretCall {
                prefix: &source[i..prefix_end],
                body: &source[prefix_end..closing_quote],
                suffix: &source[closing_quote..call_end],
            });
            i = call_end;
            emit_passthrough_start = call_end;
        } else {
            i += 1;
        }
    }
    if emit_passthrough_start < bytes.len() {
        out.push(Chunk::Passthrough(&source[emit_passthrough_start..]));
    }
    out
}

/// The literal sequence we recognise as the opener.
const SECRET_PREFIX: &str = "secret(\"";

/// If `bytes[i..]` starts with `secret("BODY")` (where BODY
/// contains no `"` or `\` characters), return the byte offset
/// (exclusive) of the closing `)`.  Otherwise return `None`.
///
/// The MVP-restricted body charset is documented at the module
/// level — operators wanting embedded quotes or backslashes need
/// the production layer-7 with full Python tokenization.
fn try_match_secret_call(bytes: &[u8], i: usize) -> Option<usize> {
    let prefix = SECRET_PREFIX.as_bytes();
    if bytes.len() < i + prefix.len() {
        return None;
    }
    if &bytes[i..i + prefix.len()] != prefix {
        return None;
    }
    // Find closing quote.  Restrict body charset to ASCII non-
    // quote, non-backslash to keep the MVP scanner trivial.
    let body_start = i + prefix.len();
    let mut j = body_start;
    while j < bytes.len() && bytes[j] != b'"' {
        if bytes[j] == b'\\' {
            return None;
        }
        j += 1;
    }
    if j >= bytes.len() {
        return None;
    }
    // bytes[j] is the closing quote.  Expect `)` immediately after.
    if j + 1 >= bytes.len() || bytes[j + 1] != b')' {
        return None;
    }
    Some(j + 2)
}

#[cfg(test)]
mod tests {
    use super::{
        derive_compound, scramble_secret_literals,
        unscramble_secret_literals, walk_secret_calls, Chunk,
        COMPOUND_WORD_COUNT,
    };
    use babbleon_core_v2::per_host_secret::PerHostSecret;
    use babbleon_core_v2::wordlist::Wordlist;
    use std::collections::HashMap;

    fn fixed_secret() -> PerHostSecret {
        PerHostSecret::from_bytes(&[0xAB; 32]).unwrap()
    }

    #[test]
    fn walker_emits_single_passthrough_when_no_secret_call() {
        let chunks = walk_secret_calls("def f(): return 42");
        assert_eq!(chunks.len(), 1);
        match &chunks[0] {
            Chunk::Passthrough(s) => assert_eq!(*s, "def f(): return 42"),
            Chunk::SecretCall { .. } => panic!("unexpected SecretCall"),
        }
    }

    #[test]
    fn walker_splits_around_single_secret_call() {
        let chunks =
            walk_secret_calls(r#"prefix secret("xyz") suffix"#);
        assert_eq!(chunks.len(), 3);
        match &chunks[0] {
            Chunk::Passthrough(s) => assert_eq!(*s, "prefix "),
            Chunk::SecretCall { .. } => {
                panic!("expected Passthrough, got SecretCall")
            }
        }
        match &chunks[1] {
            Chunk::SecretCall { prefix, body, suffix } => {
                assert_eq!(*prefix, "secret(\"");
                assert_eq!(*body, "xyz");
                assert_eq!(*suffix, "\")");
            }
            Chunk::Passthrough(_) => {
                panic!("expected SecretCall, got Passthrough")
            }
        }
        match &chunks[2] {
            Chunk::Passthrough(s) => assert_eq!(*s, " suffix"),
            Chunk::SecretCall { .. } => {
                panic!("expected Passthrough, got SecretCall")
            }
        }
    }

    #[test]
    fn walker_handles_multiple_secret_calls() {
        let chunks = walk_secret_calls(
            r#"x = secret("aa"); y = secret("bb")"#,
        );
        // Expect 4 chunks: passthrough, call, passthrough, call.
        assert_eq!(chunks.len(), 4);
        match &chunks[1] {
            Chunk::SecretCall { body, .. } => assert_eq!(*body, "aa"),
            Chunk::Passthrough(_) => {
                panic!("expected SecretCall at index 1")
            }
        }
        match &chunks[3] {
            Chunk::SecretCall { body, .. } => assert_eq!(*body, "bb"),
            Chunk::Passthrough(_) => {
                panic!("expected SecretCall at index 3")
            }
        }
    }

    #[test]
    fn walker_ignores_secret_call_with_backslash_in_body() {
        // MVP scanner refuses bodies containing backslashes.  A
        // body like "a\nb" would need escape handling we have not
        // implemented; the scanner falls through to passthrough.
        let chunks =
            walk_secret_calls(r#"secret("a\nb") rest"#);
        // The whole thing should be one passthrough — no SecretCall.
        for c in &chunks {
            assert!(
                !matches!(c, Chunk::SecretCall { .. }),
                "scanner must skip backslash-containing bodies",
            );
        }
    }

    #[test]
    fn walker_ignores_unclosed_secret_call() {
        let chunks = walk_secret_calls(r#"secret("unclosed"#);
        for c in &chunks {
            assert!(!matches!(c, Chunk::SecretCall { .. }));
        }
    }

    #[test]
    fn walker_ignores_secret_call_missing_closing_paren() {
        let chunks = walk_secret_calls(r#"secret("ok"x"#);
        for c in &chunks {
            assert!(!matches!(c, Chunk::SecretCall { .. }));
        }
    }

    #[test]
    fn derive_compound_is_deterministic() {
        let s = fixed_secret();
        let wl = Wordlist::english_baseline();
        let a = derive_compound(&s, 0, "hunter2", wl).unwrap();
        let b = derive_compound(&s, 0, "hunter2", wl).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn derive_compound_changes_with_body() {
        let s = fixed_secret();
        let wl = Wordlist::english_baseline();
        let a = derive_compound(&s, 0, "hunter2", wl).unwrap();
        let b = derive_compound(&s, 0, "hunter3", wl).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn derive_compound_changes_with_epoch() {
        let s = fixed_secret();
        let wl = Wordlist::english_baseline();
        let a = derive_compound(&s, 0, "hunter2", wl).unwrap();
        let b = derive_compound(&s, 1, "hunter2", wl).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn derive_compound_changes_with_secret() {
        let s1 = fixed_secret();
        let s2 = PerHostSecret::from_bytes(&[0xCD; 32]).unwrap();
        let wl = Wordlist::english_baseline();
        let a = derive_compound(&s1, 0, "hunter2", wl).unwrap();
        let b = derive_compound(&s2, 0, "hunter2", wl).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn derive_compound_is_n_words_concatenated() {
        let s = fixed_secret();
        let wl = Wordlist::english_baseline();
        let compound = derive_compound(&s, 0, "x", wl).unwrap();
        // Compound contains COMPOUND_WORD_COUNT wordlist entries.
        // Each entry is a single English word, no spaces.  Cannot
        // assert the word count exactly without re-splitting, but
        // can assert plausibility: compound is non-empty and
        // contains only ASCII lowercase letters.
        assert!(!compound.is_empty());
        for ch in compound.chars() {
            assert!(
                ch.is_ascii_lowercase(),
                "compound contains non-lowercase {ch:?}: {compound}",
            );
        }
        // Compound is at least 4 chars (smallest 4 wordlist words
        // each have at least one char each — empirically the
        // baseline's shortest words are 1-2 chars).
        assert!(compound.len() >= COMPOUND_WORD_COUNT);
    }

    #[test]
    fn scramble_replaces_literal_body_with_compound() {
        let src = r#"PASSWORD = secret("hunter2")"#;
        let (out, mapping) =
            scramble_secret_literals(src, &fixed_secret(), 0).unwrap();
        assert!(!out.contains("hunter2"), "literal must be gone: {out}");
        assert!(out.contains("PASSWORD = secret(\""));
        assert!(out.ends_with("\")"));
        assert_eq!(mapping.len(), 1);
        for (compound, body) in &mapping {
            assert_eq!(body, "hunter2");
            assert!(out.contains(compound));
        }
    }

    #[test]
    fn scramble_then_unscramble_round_trips() {
        let src = r#"a = secret("alpha"); b = secret("bravo")"#;
        let (out, mapping) =
            scramble_secret_literals(src, &fixed_secret(), 0).unwrap();
        let back = unscramble_secret_literals(&out, &mapping);
        assert_eq!(back, src);
    }

    #[test]
    fn scramble_is_deterministic() {
        let src = r#"x = secret("a"); y = secret("b")"#;
        let (a, _) =
            scramble_secret_literals(src, &fixed_secret(), 0).unwrap();
        let (b, _) =
            scramble_secret_literals(src, &fixed_secret(), 0).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn scramble_with_no_secret_calls_is_identity() {
        let src = "def hello(): return 42";
        let (out, mapping) =
            scramble_secret_literals(src, &fixed_secret(), 0).unwrap();
        assert_eq!(out, src);
        assert!(mapping.is_empty());
    }

    #[test]
    fn unscramble_with_empty_mapping_leaves_compounds_untouched() {
        let src = r#"x = secret("compoundbody")"#;
        let back = unscramble_secret_literals(src, &HashMap::new());
        assert_eq!(back, src);
    }

    #[test]
    fn two_secret_calls_with_same_body_share_one_mapping_entry() {
        let src = r#"a = secret("dup"); b = secret("dup")"#;
        let (out, mapping) =
            scramble_secret_literals(src, &fixed_secret(), 0).unwrap();
        // Same body → same compound → one mapping entry.
        assert_eq!(mapping.len(), 1);
        // And the scrambled output contains the compound twice.
        let compound = mapping.keys().next().unwrap();
        assert_eq!(out.matches(compound.as_str()).count(), 2);
    }
}
