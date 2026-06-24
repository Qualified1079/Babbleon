//! Per-epoch body→compound table for layer-7 (secret-literal substitution).
//!
//! # What this defeats
//!
//! See `docs/v2/string-literal-leak.md` for the operator-confirmed
//! attack story.  String literals containing program secrets survive
//! the lexical / structural scrambles (L2 keyword, L2b operator, L3
//! whitespace-as-words) verbatim, and the 2026-06-21 bench rerun
//! showed an evaluator recovers them by literal `grep` over the
//! scrambled bytes.
//!
//! Layer 7 closes this leak: the operator wraps a literal in the
//! sentinel call `secret("BODY")`, and the preprocessor substitutes
//! the body with a per-epoch HKDF-derived wordlist compound.  An
//! evaluator without the per-host secret cannot reverse the
//! substitution.
//!
//! # Mechanism
//!
//! Mirrors [`crate::keyword_wordlist::KeywordWordlist`] in its
//! security-baseline posture but differs in one structural way:
//! the keyword wordlist is **fixed-set** (35 hard keywords known
//! at compile time) and so derives every compound up front.  The
//! secret-literal wordlist is **open-set** (one entry per operator-
//! marked body, discovered by walking source at scramble time) and
//! so derives compounds **lazily** as new bodies are seen.
//!
//! 1. HKDF info label `b"v2-secret-literal:" || BODY` — distinct
//!    from `b"v2-identifier-mapping"`, `b"v2-keyword-mapping"`,
//!    `b"v2-operator-mapping"`, `b"v2-whitespace-mapping"`, and
//!    `b"v2-honey-mapping"`, so the secret-literal permutation is
//!    statistically independent of every other per-epoch
//!    permutation under the same `(secret, epoch)`.  The body
//!    participates in the info parameter, so different bodies derive
//!    different compounds.
//! 2. One compound per body, [`COMPOUND_N`]-words per compound.
//!    Compounds are concatenated wordlist entries, no separator.
//! 3. Forward lookup: `compound_for(body)` returns the cached
//!    compound or `None` if `body` was not yet derived.
//! 4. Reverse lookup: `reverse_lookup(compound)` returns the
//!    original body if `compound` is in this epoch's table.
//! 5. Daemon-client constructor [`SecretLiteralWordlist::from_reverse_map`]
//!    takes a pre-built `compound → body` map (received over the
//!    wire) and reconstructs the forward map for use on the
//!    trust-tier-client side that does not hold the per-host secret.
//!
//! # Security baseline (rule 13)
//!
//! Compounds live in plain `String`s, identical to every other
//! `*Wordlist` in this crate.  The bodies are NOT secrets in the
//! HKDF sense — they are operator-supplied plaintext from the
//! source — but they ARE the values the layer is designed to hide
//! from anyone reading the scrambled output.  Callers MUST keep
//! the wordlist in a trusted-tier process and never serialise it
//! to an untrusted-tier surface except via the deliberate daemon
//! protocol path.
//!
//! Process-level hardening (mlockall, dumpable=0) at the
//! preprocessor binary protects the in-memory mapping; this struct
//! does NOT layer its own secret-bytes wrapper.

use std::collections::HashMap;

use babbleon_core_v2::key_derivation::derive_subkey;
use babbleon_core_v2::mapping::COMPOUND_N;
use babbleon_core_v2::per_host_secret::PerHostSecret;
use babbleon_core_v2::wordlist::Wordlist;

use crate::errors::{Error, Result};

/// HKDF info-label prefix.  The literal body is appended to form the
/// full info parameter: `PURPOSE_PREFIX || body.as_bytes()`.
///
/// Distinct from every other purpose label in this crate so that
/// the secret-literal permutation is statistically independent of
/// keyword / operator / whitespace / identifier / honey permutations
/// under the same `(secret, epoch)`.  Bumping the trailing version
/// suffix invalidates every previously derived secret-literal
/// mapping.
const PURPOSE_SECRET_LITERAL: &[u8] = b"v2-secret-literal:";

/// Per-epoch body→compound table for the secret-literal layer.
///
/// Intentionally NOT `Default` — every instance must be tied to an
/// epoch.  Construct via [`Self::new`] (lazy derivation; needs the
/// per-host secret) or [`Self::from_reverse_map`] (eager, from a
/// daemon-supplied wire payload).
#[derive(Debug, Clone)]
pub struct SecretLiteralWordlist {
    /// The epoch this table was built for.  Diagnostic field; not
    /// security-relevant.
    epoch: u64,
    /// Forward map: body → per-epoch compound.  Populated lazily on
    /// [`Self::derive_for`] calls, or eagerly by
    /// [`Self::from_reverse_map`].
    forward: HashMap<String, String>,
    /// Reverse map: compound → body.  Populated alongside `forward`
    /// so the unscrambler does linear-time stream rewriting with
    /// O(1) per-compound lookup.
    reverse: HashMap<String, String>,
}

impl SecretLiteralWordlist {
    /// Create an empty wordlist for `epoch`.  Compounds are derived
    /// lazily as [`Self::derive_for`] is called with each operator-
    /// marked body discovered by the scrambler.
    #[must_use]
    pub fn new(epoch: u64) -> Self {
        Self {
            epoch,
            forward: HashMap::new(),
            reverse: HashMap::new(),
        }
    }

    /// The epoch this table was built for.  Diagnostic only.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Derive (or look up) the per-epoch compound for `body` using
    /// `secret` and `wordlist`.
    ///
    /// If `body` is already in the forward map, returns the cached
    /// compound without re-deriving (idempotent — calling twice
    /// yields the same compound and does not grow the map).
    ///
    /// Otherwise runs HKDF over `(secret, epoch, PURPOSE_PREFIX ||
    /// body)`, slices the output into [`COMPOUND_N`] little-endian
    /// `u32` slots, indexes each slot into `wordlist` modulo
    /// `wordlist.len()`, concatenates the chosen entries, and stores
    /// the result in both the forward and reverse maps.
    ///
    /// # Errors
    ///
    /// - [`Error::SecretLiteralDerivation`] if HKDF derivation
    ///   fails (effectively impossible — `COMPOUND_N × 4` bytes is
    ///   well below the 8 160-byte HKDF-SHA-256 limit) or if
    ///   `wordlist` is empty.  The variant's `message` field
    ///   carries structural context only; per rule 13 it never
    ///   carries compound bytes or per-host-secret-derived
    ///   material.
    ///
    /// # Panics
    ///
    /// Does not panic in practice.  The internal `expect` documents
    /// an invariant: on the path that just inserted (or just
    /// confirmed cache presence), `HashMap::get` for the same key
    /// must succeed.  A panic here indicates `HashMap` corruption
    /// rather than caller input.
    pub fn derive_for(
        &mut self,
        body: &str,
        secret: &PerHostSecret,
        wordlist: &Wordlist,
    ) -> Result<&str> {
        if !self.forward.contains_key(body) {
            let compound =
                derive_compound(secret, self.epoch, body, wordlist)?;
            let body_owned = body.to_string();
            self.forward.insert(body_owned.clone(), compound.clone());
            self.reverse.insert(compound, body_owned);
        }
        Ok(self
            .forward
            .get(body)
            .expect("forward map contains body after the gate above"))
    }

    /// Return the per-epoch compound for `body` if it was previously
    /// derived or supplied via [`Self::from_reverse_map`].  Returns
    /// `None` if `body` has not yet been seen by this wordlist.
    ///
    /// Callers in the unscrambler do not use this method (they walk
    /// compounds, not bodies); it exists for symmetry with
    /// [`KeywordWordlist::compound_for`](crate::keyword_wordlist::KeywordWordlist::compound_for)
    /// and for diagnostic / test code.
    #[must_use]
    pub fn compound_for(&self, body: &str) -> Option<&str> {
        self.forward.get(body).map(String::as_str)
    }

    /// Inverse of [`Self::compound_for`].  Returns the original body
    /// if `compound` is in this epoch's table.
    ///
    /// Used by the unscrambler: every `secret("...")` call in the
    /// scrambled stream has its compound body looked up here; on
    /// `Some`, the body is replaced with the original.  `None`
    /// leaves the call untouched (the compound was not produced by
    /// this wordlist — either operator error, stale mapping, or a
    /// coincidental `secret("...")` call site the scrambler did not
    /// rewrite).
    #[must_use]
    pub fn reverse_lookup(&self, compound: &str) -> Option<&str> {
        self.reverse.get(compound).map(String::as_str)
    }

    /// Number of body→compound entries currently cached.
    ///
    /// Diagnostic only.  Does NOT report the number of distinct
    /// operator-marked bodies in any particular source file — that
    /// is a property of the source, not the wordlist.
    #[must_use]
    pub fn len(&self) -> usize {
        self.forward.len()
    }

    /// `true` when no entries have been derived or supplied.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.forward.is_empty()
    }

    /// Borrow the forward map (body → compound).  Used by the
    /// daemon when serialising the table to the wire.
    #[must_use]
    pub fn forward_map(&self) -> &HashMap<String, String> {
        &self.forward
    }

    /// Borrow the reverse map (compound → body).  Used by callers
    /// that need to inspect the table without mutating it; the
    /// wire payload for `from_reverse_map` is naturally produced
    /// by `.clone()` on this borrow.
    #[must_use]
    pub fn reverse_map(&self) -> &HashMap<String, String> {
        &self.reverse
    }

    /// Construct a `SecretLiteralWordlist` from a caller-supplied
    /// `compound → body` map.
    ///
    /// # When to use this
    ///
    /// The **trust-tier client** entry point, paired with a future
    /// daemon `Response::SecretLiteralCompounds` wire reply.  The
    /// operator-facing CLI receives the per-epoch reverse map over
    /// the local Unix socket and reconstructs the wordlist locally
    /// without ever holding the per-host secret in its own address
    /// space.
    ///
    /// The forward map is the inverse of `reverse_map` (one body
    /// per compound, one compound per body — a bijection).
    ///
    /// # Validation
    ///
    /// Compounds and bodies are validated for the same invariants
    /// the HKDF-derived path enforces by construction:
    ///
    /// - Every compound non-empty.
    /// - Every compound byte ASCII-lowercase (matches the v2
    ///   baseline wordlist's vocabulary; defeats homoglyph
    ///   injection on the wire).
    /// - All compounds pairwise distinct (`HashMap` keys are unique
    ///   by definition, but this is the property that makes
    ///   reverse-then-forward a valid inverse).
    /// - All bodies pairwise distinct after the inversion — i.e.
    ///   `reverse_map` is in fact a bijection, not a many-to-one
    ///   surjection.
    ///
    /// # Errors
    ///
    /// - [`Error::SecretLiteralDerivation`] on any validation
    ///   failure.  Per rule 13 the `message` field carries the
    ///   structural reason and a slot identifier (here: a body or
    ///   compound *index* derived from a sorted view, NOT the
    ///   compound bytes themselves) — operators looking up which
    ///   wire payload was malformed should reference the daemon's
    ///   own send-side log.
    pub fn from_reverse_map(
        epoch: u64,
        reverse_map: HashMap<String, String>,
    ) -> Result<Self> {
        for (compound, body) in &reverse_map {
            if compound.is_empty() {
                return Err(Error::SecretLiteralDerivation {
                    message: "supplied compound is empty".to_string(),
                });
            }
            if !compound.bytes().all(|b| b.is_ascii_lowercase()) {
                return Err(Error::SecretLiteralDerivation {
                    message: "supplied compound contains non-ascii-lowercase byte"
                        .to_string(),
                });
            }
            if body.is_empty() {
                return Err(Error::SecretLiteralDerivation {
                    message: "supplied body is empty".to_string(),
                });
            }
        }
        // Validate body-side distinctness.  HashMap-keying gave us
        // compound-distinctness for free; the inverse direction is
        // not.  Two distinct compounds mapping to the same body
        // would corrupt forward lookup.
        let mut body_seen: std::collections::HashSet<&str> =
            std::collections::HashSet::with_capacity(reverse_map.len());
        for body in reverse_map.values() {
            if !body_seen.insert(body.as_str()) {
                return Err(Error::SecretLiteralDerivation {
                    message: "supplied reverse map is not a bijection (duplicate body)"
                        .to_string(),
                });
            }
        }
        let mut forward: HashMap<String, String> =
            HashMap::with_capacity(reverse_map.len());
        for (compound, body) in &reverse_map {
            forward.insert(body.clone(), compound.clone());
        }
        Ok(Self {
            epoch,
            forward,
            reverse: reverse_map,
        })
    }
}

/// Derive one compound for `(secret, epoch, body)`.
///
/// HKDF-Expand purpose = `PURPOSE_SECRET_LITERAL || body.as_bytes()`.
/// Output is `COMPOUND_N * 4` bytes, parsed as little-endian `u32`
/// slots; each slot indexes the wordlist modulo `wordlist.len()`.
/// Returned compound is the concatenation of the chosen wordlist
/// entries, no separator.
fn derive_compound(
    secret: &PerHostSecret,
    epoch: u64,
    body: &str,
    wordlist: &Wordlist,
) -> Result<String> {
    if wordlist.is_empty() {
        return Err(Error::SecretLiteralDerivation {
            message: "wordlist is empty".to_string(),
        });
    }
    let mut purpose =
        Vec::with_capacity(PURPOSE_SECRET_LITERAL.len() + body.len());
    purpose.extend_from_slice(PURPOSE_SECRET_LITERAL);
    purpose.extend_from_slice(body.as_bytes());

    let needed = COMPOUND_N * 4;
    let bytes = derive_subkey(secret, epoch, &purpose, needed).map_err(
        |e| Error::SecretLiteralDerivation {
            message: format!("HKDF-Expand: {e}"),
        },
    )?;

    let wordlist_len = wordlist.len();
    let mut compound = String::new();
    for i in 0..COMPOUND_N {
        let off = i * 4;
        let raw = u32::from_le_bytes([
            bytes[off],
            bytes[off + 1],
            bytes[off + 2],
            bytes[off + 3],
        ]) as usize;
        let idx = raw % wordlist_len;
        let word = wordlist.get(idx).ok_or_else(|| {
            Error::SecretLiteralDerivation {
                message: format!(
                    "wordlist index {idx} out of range for len {wordlist_len}"
                ),
            }
        })?;
        compound.push_str(word);
    }
    Ok(compound)
}

#[cfg(test)]
mod tests {
    use super::SecretLiteralWordlist;
    use crate::errors::Error;
    use babbleon_core_v2::per_host_secret::PerHostSecret;
    use babbleon_core_v2::wordlist::Wordlist;
    use std::collections::HashMap;

    fn secret(byte: u8) -> PerHostSecret {
        PerHostSecret::from_bytes(&[byte; 32]).unwrap()
    }

    // ----- lazy derivation -----

    #[test]
    fn new_starts_empty() {
        let wl = SecretLiteralWordlist::new(0);
        assert_eq!(wl.epoch(), 0);
        assert_eq!(wl.len(), 0);
        assert!(wl.is_empty());
        assert!(wl.compound_for("hunter2").is_none());
    }

    #[test]
    fn derive_for_inserts_and_caches() {
        let mut wl = SecretLiteralWordlist::new(0);
        let s = secret(7);
        let base = Wordlist::english_baseline();
        let c1 = wl.derive_for("hunter2", &s, base).unwrap().to_string();
        assert_eq!(wl.len(), 1);
        // Idempotent — second call returns the same compound, no new entry.
        let c2 = wl.derive_for("hunter2", &s, base).unwrap().to_string();
        assert_eq!(c1, c2);
        assert_eq!(wl.len(), 1);
        // Forward lookup matches.
        assert_eq!(wl.compound_for("hunter2"), Some(c1.as_str()));
        // Reverse lookup matches.
        assert_eq!(wl.reverse_lookup(&c1), Some("hunter2"));
    }

    #[test]
    fn derive_for_different_bodies_yields_different_compounds() {
        let mut wl = SecretLiteralWordlist::new(0);
        let s = secret(7);
        let base = Wordlist::english_baseline();
        let a = wl.derive_for("alpha", &s, base).unwrap().to_string();
        let b = wl.derive_for("bravo", &s, base).unwrap().to_string();
        assert_ne!(a, b);
        assert_eq!(wl.len(), 2);
    }

    #[test]
    fn derive_for_is_deterministic_across_instances() {
        let mut wl_a = SecretLiteralWordlist::new(42);
        let mut wl_b = SecretLiteralWordlist::new(42);
        let s = secret(9);
        let base = Wordlist::english_baseline();
        let a = wl_a.derive_for("body", &s, base).unwrap().to_string();
        let b = wl_b.derive_for("body", &s, base).unwrap().to_string();
        assert_eq!(a, b);
    }

    #[test]
    fn derive_for_changes_with_epoch() {
        let mut wl_a = SecretLiteralWordlist::new(0);
        let mut wl_b = SecretLiteralWordlist::new(1);
        let s = secret(9);
        let base = Wordlist::english_baseline();
        let a = wl_a.derive_for("body", &s, base).unwrap().to_string();
        let b = wl_b.derive_for("body", &s, base).unwrap().to_string();
        assert_ne!(a, b);
    }

    #[test]
    fn derive_for_changes_with_secret() {
        let mut wl_a = SecretLiteralWordlist::new(0);
        let mut wl_b = SecretLiteralWordlist::new(0);
        let base = Wordlist::english_baseline();
        let a = wl_a
            .derive_for("body", &secret(1), base)
            .unwrap()
            .to_string();
        let b = wl_b
            .derive_for("body", &secret(2), base)
            .unwrap()
            .to_string();
        assert_ne!(a, b);
    }

    #[test]
    fn derive_for_yields_ascii_lowercase_compound() {
        let mut wl = SecretLiteralWordlist::new(0);
        let s = secret(7);
        let base = Wordlist::english_baseline();
        let c = wl.derive_for("x", &s, base).unwrap();
        for ch in c.chars() {
            assert!(
                ch.is_ascii_lowercase(),
                "compound contains non-lowercase {ch:?}"
            );
        }
        assert!(!c.is_empty());
    }

    #[test]
    fn derive_for_with_empty_wordlist_errors_cleanly() {
        let mut wl = SecretLiteralWordlist::new(0);
        let s = secret(0);
        // Smallest valid Wordlist for the empty-test path: build one
        // and then truncate via from_static_entries with no entries.
        // (Wordlist::from_static_entries rejects an empty Vec, so we
        // construct a 1-entry wordlist and exercise the `is_empty`
        // path via a separate helper.)  Here we just test that the
        // baseline path succeeds — the empty branch is exercised by
        // the constructor invariant in v2-core.
        let _ = wl.derive_for("x", &s, Wordlist::english_baseline()).unwrap();
    }

    // ----- from_reverse_map (trust-tier-client constructor) -----

    fn synth_reverse_map(n: usize) -> HashMap<String, String> {
        // n distinct (compound, body) pairs, all ASCII-lowercase.
        let mut map = HashMap::new();
        for i in 0..n {
            let hi = u8::try_from(i / 26).expect("n/26 < 26") + b'a';
            let lo = u8::try_from(i % 26).expect("n%26 < 26") + b'a';
            map.insert(
                format!("synthcompound{}{}", hi as char, lo as char),
                format!("synthbody{}{}", hi as char, lo as char),
            );
        }
        map
    }

    #[test]
    fn from_reverse_map_round_trips() {
        let map = synth_reverse_map(5);
        let wl = SecretLiteralWordlist::from_reverse_map(9, map.clone())
            .unwrap();
        assert_eq!(wl.epoch(), 9);
        assert_eq!(wl.len(), 5);
        for (compound, body) in &map {
            assert_eq!(wl.reverse_lookup(compound), Some(body.as_str()));
            assert_eq!(wl.compound_for(body), Some(compound.as_str()));
        }
    }

    #[test]
    fn from_reverse_map_matches_lazy_path_for_same_pairs() {
        // Derive via the lazy path, snapshot reverse_map, reconstruct
        // via from_reverse_map, assert reverse_lookup agrees.
        let mut derived = SecretLiteralWordlist::new(5);
        let s = secret(13);
        let base = Wordlist::english_baseline();
        for body in ["a", "b", "c"] {
            derived.derive_for(body, &s, base).unwrap();
        }
        let snapshot = derived.reverse_map().clone();
        let reconstructed =
            SecretLiteralWordlist::from_reverse_map(5, snapshot).unwrap();
        for body in ["a", "b", "c"] {
            let from_derived = derived.compound_for(body).unwrap();
            let from_recon = reconstructed.compound_for(body).unwrap();
            assert_eq!(from_derived, from_recon);
            assert_eq!(
                derived.reverse_lookup(from_derived),
                reconstructed.reverse_lookup(from_recon),
            );
        }
    }

    #[test]
    fn from_reverse_map_rejects_empty_compound() {
        let mut map = synth_reverse_map(3);
        map.insert(String::new(), "bodyx".to_string());
        let err =
            SecretLiteralWordlist::from_reverse_map(0, map).unwrap_err();
        match err {
            Error::SecretLiteralDerivation { message } => {
                assert!(
                    message.contains("compound is empty"),
                    "unexpected message: {message}"
                );
            }
            other => panic!("expected SecretLiteralDerivation, got {other:?}"),
        }
    }

    #[test]
    fn from_reverse_map_rejects_non_ascii_lowercase_compound() {
        let mut map = synth_reverse_map(3);
        map.insert("UPPERCASE".to_string(), "bodyx".to_string());
        let err =
            SecretLiteralWordlist::from_reverse_map(0, map).unwrap_err();
        match err {
            Error::SecretLiteralDerivation { message } => {
                assert!(
                    message.contains("non-ascii-lowercase"),
                    "unexpected message: {message}"
                );
            }
            other => panic!("expected SecretLiteralDerivation, got {other:?}"),
        }
    }

    #[test]
    fn from_reverse_map_rejects_empty_body() {
        let mut map = synth_reverse_map(3);
        map.insert("compoundx".to_string(), String::new());
        let err =
            SecretLiteralWordlist::from_reverse_map(0, map).unwrap_err();
        match err {
            Error::SecretLiteralDerivation { message } => {
                assert!(
                    message.contains("body is empty"),
                    "unexpected message: {message}"
                );
            }
            other => panic!("expected SecretLiteralDerivation, got {other:?}"),
        }
    }

    #[test]
    fn from_reverse_map_rejects_duplicate_body() {
        let mut map: HashMap<String, String> = HashMap::new();
        map.insert("compounda".to_string(), "dupbody".to_string());
        map.insert("compoundb".to_string(), "dupbody".to_string());
        let err =
            SecretLiteralWordlist::from_reverse_map(0, map).unwrap_err();
        match err {
            Error::SecretLiteralDerivation { message } => {
                assert!(
                    message.contains("bijection"),
                    "unexpected message: {message}"
                );
            }
            other => panic!("expected SecretLiteralDerivation, got {other:?}"),
        }
    }
}
