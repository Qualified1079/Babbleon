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
//! The preprocessor implements **six composable layers** of the v2
//! structural scramble.  Source code is reduced to a noisy wall of
//! random words with no visible language, structure, or identifier
//! fingerprint.  Any tool that reads the file by `read()` — `cat`,
//! `less`, `grep`, `rg`, every editor without the v2 plugin — sees
//! a token soup with no line, indent, or block boundaries to
//! position-match against.
//!
//! # Mechanism
//!
//! Layer modules, in the order they apply on scramble:
//!
//! - **L4** ([`chunk_reorder`]) — top-level chunks reordered by a
//!   per-epoch shuffle; each chunk carries a `__bbnpos<N>__` marker
//!   the unscrambler reads to restore original order.
//! - **L5** ([`decoy_injection`]) — depth-0 `__bbndecoy<N>__` tokens
//!   injected at ~25% of original token count.  Stripped by prefix
//!   on unscramble.
//! - **L2** ([`identifier_scrambler`]) — every whitespace-delimited
//!   token replaced with one of [`ALIAS_COUNT`] per-epoch HKDF-
//!   derived compound aliases.  Multi-alias cycling defeats
//!   frequency analysis.
//! - **L3** ([`scrambler`] + [`unscrambler`]) — whitespace markers
//!   replaced by per-epoch wordlist compounds.  Greedy
//!   longest-prefix match drives the inverse.
//! - **L6** ([`direction_reversal`]) — variable-length char chunks
//!   of the body reversed per a per-epoch xorshift PRNG (involutive).
//! - **L12** ([`tokenizer_noise`]) — zero-width characters (ZWSP /
//!   ZWNJ / ZWJ) injected at deterministic per-epoch positions;
//!   Cyrillic-homoglyph substitution for `a c e i o p x y` on a
//!   ~1/3 PRNG draw.  Strip is content-based and idempotent.
//!
//! Cross-cutting modules:
//!
//! - [`tokens`] — the abstract `Token` IR.  A `Token` is either a
//!   `Whitespace(WhitespaceKind)` marker or a `Word(String)`.
//! - [`python_tokenizer`] — minimal Python tokenizer.  Walks bytes;
//!   classifies whitespace runs; emits `Token::Word` for non-
//!   whitespace runs.  MVP limitations documented at
//!   `python_tokenizer::MVP_LIMITATIONS`.
//! - [`whitespace_wordlist`] — per-epoch 5-compound table (one per
//!   `WhitespaceKind`) via HKDF + Fisher-Yates; info label
//!   `b"v2-whitespace-mapping"` for statistical independence from
//!   the identifier + honey permutations.
//! - [`file_format`] — `babbleon-v2` header encode + decode; format
//!   version 0 (legacy, pre-L6 + pre-L12) and version 1 (current).
//! - [`pipeline`] — full composition of the six layers + the file
//!   format.  `scramble_pipeline` and `unscramble_pipeline` are the
//!   canonical entry points; the user CLI, the corpus CLI, and the
//!   python-shim all consume them.
//! - [`secret_literal_scrambler`] + [`secret_literal_wordlist`] —
//!   optional pre-pass for `secret("body")` literals; gated on
//!   operator opt-in.
//!
//! # Trust placement (load-bearing)
//!
//! The preprocessor runs **only in the trusted tier** — never in an
//! untrusted-tier process.  See `docs/v2/structure-scrambling.md`
//! §"Trust placement" and §"Same hardening as the daemon" for the
//! full attack surface.  This crate is the library; the binaries
//! (with `mlockall`, `PR_SET_DUMPABLE=0`, `RLIMIT_CORE=0`, and a
//! seccomp profile) live in `crates/v2-babbleon` (the `babbleon
//! scramble` / `babbleon unscramble` CLI) and
//! `crates/v2-babbleon-python-shim` (the `babbleon-python` runtime
//! entry point).
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
//! # Current scope (post-2026-06-26)
//!
//! - Whitespace wordlist derivation ([`whitespace_wordlist`]).
//! - Token IR ([`tokens`]) + minimal Python tokenizer
//!   ([`python_tokenizer`]).
//! - All six production layers (L2 / L3 / L4 / L5 / L6 / L12).
//! - File-format encode + decode ([`file_format`]) including the
//!   legacy v0 layout for back-compat.
//! - Full pipeline composition ([`pipeline`]) consumed by the
//!   `babbleon scramble`/`unscramble` CLI, the `scramble-dir`/
//!   `unscramble-dir` batch CLI, and the `babbleon-python` runtime
//!   shim.
//! - Optional secret-literal pre-pass
//!   ([`secret_literal_scrambler`] + [`secret_literal_wordlist`]).
//! - Round-trip property tests + Python-execution integration tests.
//!
//! # Out of scope (filed for future commits)
//!
//! - Full Python tokenization (f-strings, multi-line strings, the
//!   walrus-operator boundary, etc.) — the MVP tokenizer documents
//!   its limitations and the next revision can swap in a richer
//!   backend without changing the layer modules.
//! - Layers 7-11 (control-flow flattening, opaque predicates,
//!   constant unfolding, path-string obfuscation, defensive prompt
//!   injection) per `docs/v2/obfuscation-landscape.md`.  Each
//!   composes on top of the six existing layers.
//! - Collision detection for the rare case where a non-whitespace
//!   byte run contains a whitespace compound as a substring.  See
//!   `unscrambler::COLLISION_NOTE` for the threat model and the
//!   reserved-pool design.

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
    alias_count_for_epoch, collect_unique_tokens, scramble_identifiers,
    unscramble_identifiers, IdentifierMapping, ALIAS_COUNT,
    ALIAS_COUNT_VARIABLE_FROM_VERSION, MAX_ALIAS_COUNT, MIN_ALIAS_COUNT,
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
