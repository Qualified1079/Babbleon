//! Source-text pre-pass that substitutes `secret("BODY")` bodies
//! with per-epoch HKDF-derived compounds — layer 7 of the v2
//! structural scramble.
//!
//! # What this defeats
//!
//! See [`crate::secret_literal_wordlist`] for the threat-model
//! framing and the wordlist construction.  This module is the
//! source-walker that finds operator-marked secret literals and
//! does the substitution.
//!
//! # Pipeline placement
//!
//! Runs **before** tokenization:
//!
//! ```text
//! source → L7 (this module) → tokenize → L2 (keywords) → L2b
//!         (operators) → L3 (whitespace-as-words) → scrambled bytes
//! ```
//!
//! Operating on raw source text (not on the `Token` IR) keeps the
//! downstream layers L2/L2b/L3 unaware of secret-literal handling.
//! From their perspective the bodies are just shorter, lower-entropy
//! words.  This composition is the property the operator review of
//! 2026-06-22 required ("layers compose without cross-knowledge").
//!
//! # Scanner scope (MVP)
//!
//! The scanner walks bytes looking for the literal sequence
//! `secret("`.  On match it expects:
//!
//! - The body contains no `"` and no `\\` characters.  Bodies with
//!   escape sequences are NOT supported in the MVP — operators
//!   wanting embedded quotes or backslashes need a future revision
//!   with full Python tokenization.  The scanner falls through
//!   without rewriting the call when it encounters a backslash,
//!   so a call site with a complex body silently passes through
//!   unchanged.  Documented behaviour: operators should run
//!   `babbleon lint` (forthcoming) to catch passthrough secrets.
//! - A closing `"` followed immediately by `)`.
//!
//! Both scramble and unscramble use the same scanner so the inverse
//! is well-defined.

use crate::errors::Result;
use crate::secret_literal_wordlist::SecretLiteralWordlist;
use babbleon_core_v2::per_host_secret::PerHostSecret;
use babbleon_core_v2::wordlist::Wordlist;

/// The literal sequence the scanner recognises as a secret-call
/// opener.  Operators can change this in a future revision (e.g.
/// to `babbleon.secret("`) but the MVP fixes it to the shortest
/// readable form.
pub const SECRET_CALL_PREFIX: &str = "secret(\"";

/// Substitute every `secret("BODY")` occurrence in `source` with
/// `secret("<compound>")` where the compound is derived from
/// `(secret, epoch, BODY)` via HKDF.  The supplied `wordlist` is
/// populated in place with the body→compound entries discovered.
///
/// Bodies containing `"` or `\\` are NOT supported in the MVP and
/// are passed through unchanged (the call site emerges from the
/// scrambler with the original body intact).
///
/// Same `(secret, epoch, body)` always produces the same compound,
/// so a body appearing twice in the source maps to one compound and
/// adds exactly one wordlist entry.
///
/// # Errors
///
/// - Any [`Error::SecretLiteralDerivation`](crate::errors::Error::SecretLiteralDerivation)
///   bubbled up from the wordlist's HKDF / indexing path
///   (effectively impossible with the baseline wordlist; defensive).
pub fn scramble_secret_literals(
    source: &str,
    per_host_secret: &PerHostSecret,
    wordlist_words: &Wordlist,
    secret_literal_wordlist: &mut SecretLiteralWordlist,
) -> Result<String> {
    let mut out = String::with_capacity(source.len());
    for chunk in walk_secret_calls(source) {
        match chunk {
            Chunk::Passthrough(s) => out.push_str(s),
            Chunk::SecretCall { prefix, body, suffix } => {
                let compound = secret_literal_wordlist
                    .derive_for(body, per_host_secret, wordlist_words)?
                    .to_string();
                out.push_str(prefix);
                out.push_str(&compound);
                out.push_str(suffix);
            }
        }
    }
    Ok(out)
}

/// Inverse of [`scramble_secret_literals`].  Walks `scrambled` for
/// `secret("...")` calls; for each one whose body matches a known
/// compound in `wordlist`, substitutes the stored body back in.
///
/// Compounds not in `wordlist` are left unchanged — could be
/// operator-error (stale mapping, wrong epoch) or a coincidental
/// `secret("...")` call site the scrambler never rewrote (e.g.
/// because of a `"` or `\\` in the body that fell outside the MVP
/// scanner's grammar).  Either way the unscrambler does not error
/// on unknown compounds; it preserves the bytes so the downstream
/// interpreter sees a legal Python call.
///
/// No I/O.  Allocates one `String` for the output.
#[must_use]
pub fn unscramble_secret_literals(
    scrambled: &str,
    wordlist: &SecretLiteralWordlist,
) -> String {
    let mut out = String::with_capacity(scrambled.len());
    for chunk in walk_secret_calls(scrambled) {
        match chunk {
            Chunk::Passthrough(s) => out.push_str(s),
            Chunk::SecretCall { prefix, body, suffix } => {
                out.push_str(prefix);
                if let Some(original) = wordlist.reverse_lookup(body) {
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

/// One scan iteration's yield.  Lifetimes are tied to the source
/// string so the scanner never copies — it just slices.
#[derive(Debug)]
enum Chunk<'a> {
    /// Verbatim source bytes (not inside a `secret()` call).
    Passthrough(&'a str),
    /// A `secret("...")` call.  `prefix` is `secret("`; `suffix`
    /// is `")`; `body` is the literal body between the quotes
    /// (without escape-character processing — MVP supports only
    /// literal bodies that contain neither `"` nor `\\`).
    SecretCall {
        prefix: &'a str,
        body: &'a str,
        suffix: &'a str,
    },
}

/// Stream `source` as alternating `Passthrough` / `SecretCall`
/// chunks.  Single forward pass over the input bytes; never
/// re-scans.  See module docs for the scanner's grammar.
fn walk_secret_calls(source: &str) -> Vec<Chunk<'_>> {
    let mut out = Vec::new();
    let bytes = source.as_bytes();
    let mut i = 0;
    let mut emit_passthrough_start = 0;
    while i < bytes.len() {
        if let Some(call_end) = try_match_secret_call(bytes, i) {
            if i > emit_passthrough_start {
                out.push(Chunk::Passthrough(
                    &source[emit_passthrough_start..i],
                ));
            }
            let prefix_end = i + SECRET_CALL_PREFIX.len();
            // Find closing quote.  `try_match_secret_call` guarantees
            // it exists; the `expect` documents the invariant.
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

/// If `bytes[i..]` starts with `secret("BODY")` (where `BODY`
/// contains no `"` and no `\\` characters), return the byte offset
/// (exclusive) of the closing `)`.  Otherwise return `None`.
///
/// The MVP-restricted body charset is documented at the module
/// level.  A future revision will accept full Python string
/// literals (escape sequences, multi-line strings, f-strings).
fn try_match_secret_call(bytes: &[u8], i: usize) -> Option<usize> {
    let prefix = SECRET_CALL_PREFIX.as_bytes();
    if bytes.len() < i + prefix.len() {
        return None;
    }
    if &bytes[i..i + prefix.len()] != prefix {
        return None;
    }
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
        scramble_secret_literals, unscramble_secret_literals,
        walk_secret_calls, Chunk,
    };
    use crate::secret_literal_wordlist::SecretLiteralWordlist;
    use babbleon_core_v2::per_host_secret::PerHostSecret;
    use babbleon_core_v2::wordlist::Wordlist;

    fn secret(byte: u8) -> PerHostSecret {
        PerHostSecret::from_bytes(&[byte; 32]).unwrap()
    }

    // ----- walker -----

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
    }

    #[test]
    fn walker_ignores_secret_call_with_backslash_in_body() {
        let chunks =
            walk_secret_calls(r#"secret("a\nb") rest"#);
        for c in &chunks {
            assert!(
                !matches!(c, Chunk::SecretCall { .. }),
                "scanner must skip backslash-containing bodies"
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

    // ----- scramble -----

    #[test]
    fn scramble_replaces_literal_body_with_compound() {
        let src = r#"PASSWORD = secret("hunter2")"#;
        let s = secret(7);
        let base = Wordlist::english_baseline();
        let mut wl = SecretLiteralWordlist::new(0);
        let out =
            scramble_secret_literals(src, &s, base, &mut wl).unwrap();
        assert!(!out.contains("hunter2"), "literal must be gone: {out}");
        assert!(out.contains("PASSWORD = secret(\""));
        assert!(out.ends_with("\")"));
        assert_eq!(wl.len(), 1);
        assert!(wl.compound_for("hunter2").is_some());
    }

    #[test]
    fn scramble_then_unscramble_round_trips() {
        let src = r#"a = secret("alpha"); b = secret("bravo")"#;
        let s = secret(7);
        let base = Wordlist::english_baseline();
        let mut wl = SecretLiteralWordlist::new(0);
        let scrambled =
            scramble_secret_literals(src, &s, base, &mut wl).unwrap();
        let back = unscramble_secret_literals(&scrambled, &wl);
        assert_eq!(back, src);
    }

    #[test]
    fn scramble_is_deterministic() {
        let src = r#"x = secret("a"); y = secret("b")"#;
        let s = secret(7);
        let base = Wordlist::english_baseline();
        let mut wl_a = SecretLiteralWordlist::new(0);
        let a =
            scramble_secret_literals(src, &s, base, &mut wl_a).unwrap();
        let mut wl_b = SecretLiteralWordlist::new(0);
        let b =
            scramble_secret_literals(src, &s, base, &mut wl_b).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn scramble_with_no_secret_calls_is_identity() {
        let src = "def hello(): return 42";
        let s = secret(7);
        let base = Wordlist::english_baseline();
        let mut wl = SecretLiteralWordlist::new(0);
        let out =
            scramble_secret_literals(src, &s, base, &mut wl).unwrap();
        assert_eq!(out, src);
        assert!(wl.is_empty());
    }

    #[test]
    fn unscramble_with_empty_wordlist_leaves_compounds_untouched() {
        let src = r#"x = secret("compoundbody")"#;
        let wl = SecretLiteralWordlist::new(0);
        let back = unscramble_secret_literals(src, &wl);
        assert_eq!(back, src);
    }

    #[test]
    fn two_secret_calls_with_same_body_share_one_wordlist_entry() {
        let src = r#"a = secret("dup"); b = secret("dup")"#;
        let s = secret(7);
        let base = Wordlist::english_baseline();
        let mut wl = SecretLiteralWordlist::new(0);
        let out =
            scramble_secret_literals(src, &s, base, &mut wl).unwrap();
        assert_eq!(wl.len(), 1);
        let compound = wl.compound_for("dup").unwrap();
        assert_eq!(out.matches(compound).count(), 2);
    }

    #[test]
    fn scramble_round_trips_under_different_epochs() {
        let src = r#"k = secret("hunter2")"#;
        let s = secret(7);
        let base = Wordlist::english_baseline();
        for epoch in [0u64, 1, 42, 1_000_000] {
            let mut wl = SecretLiteralWordlist::new(epoch);
            let scrambled = scramble_secret_literals(src, &s, base, &mut wl)
                .unwrap();
            let back = unscramble_secret_literals(&scrambled, &wl);
            assert_eq!(back, src, "epoch {epoch} round-trip failed");
        }
    }

    #[test]
    fn scramble_passes_through_backslash_body_unchanged() {
        // The MVP scanner refuses bodies with backslashes; the call
        // site emerges unchanged.  No wordlist entry is created.
        let src = r#"x = secret("a\nb")"#;
        let s = secret(7);
        let base = Wordlist::english_baseline();
        let mut wl = SecretLiteralWordlist::new(0);
        let out =
            scramble_secret_literals(src, &s, base, &mut wl).unwrap();
        assert_eq!(out, src);
        assert!(wl.is_empty());
    }
}
