//! Babbleon v2 — runtime preprocessor (phase 3, layer 3).
//!
//! # What this defeats
//!
//! Structural fingerprinting.  v1's identifier-only scramble leaves
//! the visible shape of the source intact — line breaks,
//! indentation, brace patterns, block boundaries — and an attacker
//! model that has cached structural templates per host class
//! (Ubuntu / RHEL / Debian / ...) pattern-matches the *shape* of a
//! scrambled file against those templates to locate exploit
//! insertion points without ever resolving an identifier.  See
//! `docs/v2/structure-scrambling.md` for the operator-confirmed
//! attack story this crate addresses.
//!
//! The preprocessor implements **layer 3** of the v2 structural
//! scramble: whitespace as words.  Every `\n`, ` `, `\t`,
//! indent-block-open, and indent-block-close is replaced with a
//! wordlist compound drawn from a per-epoch whitespace wordlist.
//! Source code becomes one continuous text wall with no visible
//! structure.  Any tool that reads the file by `read()` — `cat`,
//! `less`, `grep`, `rg`, every editor without the v2 plugin — sees
//! a soup of unfamiliar tokens with no line, indent, or block
//! boundaries to position-match against.
//!
//! # Mechanism
//!
//! 1. **`whitespace_wordlist`** — per-epoch derivation of 5
//!    wordlist compounds (one per `WhitespaceKind`) via the v2-core
//!    HKDF + Fisher-Yates permutation primitives.  HKDF info label
//!    `b"v2-whitespace-mapping"` so the whitespace permutation is
//!    statistically independent of the identifier and honey
//!    permutations.
//! 2. **`tokens`** — the abstract `Token` IR.  A `Token` is either
//!    a `Whitespace(WhitespaceKind)` marker or a `Word(String)`
//!    holding a contiguous non-whitespace byte run.  Scramble /
//!    unscramble operate on `Token` streams, so the Python tokenizer
//!    is independently replaceable.
//! 3. **`python_tokenizer`** — minimal Python tokenizer for the
//!    phase-3 MVP.  Walks bytes; classifies whitespace runs; emits
//!    `Token::Word` for non-whitespace runs.  Does NOT understand
//!    Python expressions (no operator splitting, no string-literal
//!    awareness beyond the byte level).  Sufficient for valid Python
//!    that uses normal spacing; documented MVP limitations live at
//!    `python_tokenizer::MVP_LIMITATIONS`.
//! 4. **`scrambler`** — `Token` stream → scrambled byte string.
//!    Concatenates non-whitespace `Word` bytes verbatim and emits
//!    the per-epoch compound for each `Whitespace(kind)`.
//! 5. **`unscrambler`** — scrambled byte string → reconstructed
//!    source.  Greedy longest-prefix match against the 5 per-epoch
//!    whitespace compounds; everything between two whitespace
//!    compounds is one `Token::Word`.  Re-emits source with
//!    canonicalised whitespace and indent-width = 4 spaces.
//!
//! # Trust placement (load-bearing)
//!
//! The preprocessor runs **only in the trusted tier** — never in an
//! untrusted-tier process.  See `docs/v2/structure-scrambling.md`
//! §"Trust placement" and §"Same hardening as the daemon" for the
//! full attack surface.  This crate is the library; the binary
//! (with `mlockall`, `PR_SET_DUMPABLE=0`, `RLIMIT_CORE=0`, and its
//! own seccomp profile) lives elsewhere (forthcoming phase-3
//! commits).
//!
//! # No-disk guarantee (load-bearing for the binary, not this crate)
//!
//! Library callers must wire unscramble output to a pipe / memfd
//! consumed by the interpreter; the unscrambled bytes must never
//! land on disk.  This crate exposes byte-in-memory APIs only; it
//! does NOT write files.  Disk-write enforcement is a binary-level
//! concern.
//!
//! # Security baseline
//!
//! Per `docs/v2/security-baseline.md`:
//!
//! - `#![forbid(unsafe_code)]` at the crate root.  This crate is
//!   pure safe Rust; no `unsafe` block appears anywhere in the
//!   tree.
//! - `#![deny(missing_docs)]` — every public item is documented.
//! - `#![warn(clippy::pedantic)]` — pedantic linting enforced.
//! - Per-epoch whitespace compounds are derived from the per-host
//!   secret via HKDF (RFC 5869).  The compounds themselves live in
//!   plain `String`s held by `WhitespaceWordlist` — the same
//!   pattern v2-core's `EpochMapping` uses for identifier
//!   compounds.  Process-level hardening (mlockall + dumpable=0)
//!   protects the in-memory mapping; that's a binary concern.
//!
//! # MVP scope (this commit)
//!
//! - Whitespace wordlist derivation.
//! - Token IR.
//! - Minimal Python tokenizer.
//! - Scrambler.
//! - Unscrambler.
//! - Round-trip property tests.
//!
//! # Out of scope for the MVP (filed for future commits)
//!
//! - The standalone binary (`babbleon-preprocessor` / `babbleon
//!   scramble` / `babbleon unscramble`).
//! - The `pipe(2)` plumbing to wire unscrambled bytes into a child
//!   interpreter without a disk round-trip.
//! - Full Python tokenization (f-strings, multi-line strings, the
//!   walrus-operator boundary, etc.) — the MVP tokenizer documents
//!   its limitations and the next commit can swap in a richer
//!   backend.
//! - Layer-2 (operator scramble) and layer-4 (chunk reorder), which
//!   compose on top of this crate.
//! - Collision detection for the rare case where a non-whitespace
//!   byte run contains a whitespace compound as a substring.  See
//!   `unscrambler::COLLISION_NOTE` for the threat model and the
//!   reserved-pool design that addresses it in a future commit.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(clippy::pedantic)]

pub mod chunk_reorder;
pub mod decoy_injection;
pub mod direction_reversal;
pub mod errors;
pub mod file_format;
pub mod identifier_scrambler;
pub mod pipeline;
pub mod python_tokenizer;
pub mod scrambler;
pub mod secret_literal_scrambler;
pub mod secret_literal_wordlist;
pub mod tokenizer_noise;
pub mod tokens;
pub mod unscrambler;
pub mod whitespace_wordlist;

pub use chunk_reorder::{
    has_any_marker as has_any_chunk_marker, scramble_chunks, unscramble_chunks,
};
pub use decoy_injection::{has_any_decoy, inject_decoys, strip_decoys};
pub use direction_reversal::{reverse_chunks, unreverse_chunks};
pub use errors::{Error, Result};
pub use file_format::{
    decode as decode_scrambled_file, encode as encode_scrambled_file,
    encode_versioned as encode_scrambled_file_versioned, DecodedFile,
    FORMAT_VERSION_LATEST, FORMAT_VERSION_LEGACY,
};
pub use pipeline::{scramble_pipeline, unscramble_pipeline, ScrambledFile};
pub use identifier_scrambler::{
    collect_unique_tokens, scramble_identifiers, unscramble_identifiers,
    IdentifierMapping, ALIAS_COUNT,
};
pub use secret_literal_scrambler::{
    scramble_secret_literals, unscramble_secret_literals,
};
pub use secret_literal_wordlist::SecretLiteralWordlist;
pub use tokenizer_noise::{
    has_any_noise as has_any_tokenizer_noise, inject_noise as inject_tokenizer_noise,
    strip_noise as strip_tokenizer_noise,
};
pub use tokens::{Token, WhitespaceKind};
pub use whitespace_wordlist::WhitespaceWordlist;
