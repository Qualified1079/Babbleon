//! Babbleon v2 — scramble engine (OS-agnostic core).
//!
//! # What this is
//!
//! The pure computation at the heart of Babbleon v2's per-host
//! obfuscation: HKDF sub-key derivation, bijective Fisher-Yates
//! permutations over a wordlist, and the per-epoch name table that maps
//! canonical tool names (`curl`, `ssh`, `aws`) to per-host scrambled
//! compounds.  **No syscalls, no filesystem paths, no OS assumptions.**
//!
//! This crate was carved out of `v2-babbleon-core` (see
//! `docs/v2/scramble-core-carve.md`) so that the scramble engine can be
//! shared by two consumers that agree on the math but disagree on
//! everything else:
//!
//! - the **Linux tier** (`v2-babbleon-core`, now a facade) — welds this
//!   engine to `/proc`-based tripwires, `/bin/sh` wrapper emission, and
//!   the JSONL/ed25519 audit-chain event sinks;
//! - a **mobile fork** (Android/enterprise, later) — reuses this engine
//!   verbatim and rebuilds enforcement on SELinux, the zygote/app model,
//!   and binder/property interception instead.
//!
//! `v2-babbleon-core` re-exports every module below under its old path,
//! so existing `babbleon_core_v2::mapping::...` call sites keep
//! compiling.  New code that needs only the scramble engine (the
//! preprocessor, the mobile fork) should depend on this crate directly.
//!
//! # Modules
//!
//! - **`per_host_secret`** — the only secret on the box, held in
//!   `zeroize::Zeroizing<[u8; 32]>` so its plaintext is wiped on drop.
//! - **`key_derivation`** — HKDF-SHA-256 (RFC 5869) sub-key derivation
//!   per `(epoch, purpose)` tuple.
//! - **`permutation`** / **`permutation_cache`** — bijective
//!   Fisher-Yates over a wordlist, seeded by HKDF, with an LRU cache.
//! - **`wordlist`** — wordlist loader.
//! - **`mapping`** — `EpochMapping` (the per-epoch name table) and
//!   `MappingBuilder` (the constructor).
//! - **`crypto_compare`** — constant-time secret-byte comparison.
//! - **`errors`** — the crate's `Error` / `Result`.
//!
//! # Security baseline applied
//!
//! Per `docs/v2/security-baseline.md`: `#![forbid(unsafe_code)]` at the
//! crate root (this crate is 100% safe Rust); secret-holding types wrap
//! their bytes in `zeroize::Zeroizing`; secret-derived compares go
//! through `crypto_compare::secret_bytes_equal` (constant-time); domain
//! separation uses HKDF, not hand-rolled hash-of-concat.
//!
//! # Differential testing against v1
//!
//! `v2-babbleon-core`'s `tests/v1_compat.rs` asserts that this engine
//! produces the same compound name as v1 for the same
//! `(host_secret, epoch, tool)` triple.  That gate lives with the facade
//! (it depends on the v1 crate) and continues to exercise this engine
//! through the re-export.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(clippy::pedantic)]

pub mod crypto_compare;
pub mod errors;
pub mod key_derivation;
pub mod mapping;
pub mod per_host_secret;
pub mod permutation;
pub mod permutation_cache;
pub mod wordlist;

pub use errors::{Error, Result};
pub use mapping::{EpochMapping, MappingBuilder, COMPOUND_N, HONEY_COUNT};
pub use per_host_secret::{PerHostSecret, PER_HOST_SECRET_LEN};
pub use permutation::Permutation;
pub use permutation_cache::{
    PermutationCache, DEFAULT_CAPACITY as PERMUTATION_CACHE_DEFAULT_CAPACITY,
};
pub use wordlist::Wordlist;
