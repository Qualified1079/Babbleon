//! Babbleon v2 — core library.
//!
//! # What this defeats
//!
//! Per-host randomized namespace obfuscation: every host has its own
//! mapping from canonical tool names (`curl`, `ssh`, `aws`) to
//! per-host scrambled wordlist compounds.  The attacker model is an
//! automated LLM-driven agent that runs in an untrusted-tier process
//! and reasons about exploits using cached knowledge of canonical
//! names.  See `docs/threat-model.md` (v1) and `docs/v2/threat-model.md`
//! (v2; in flight) for the full model.
//!
//! v2 extends v1's identifier-only scramble with the
//! structural-scrambling layers from `docs/v2/structure-scrambling.md`
//! (phase 3+).
//!
//! # This crate is the Linux-tier facade
//!
//! The OS-agnostic scramble engine — `per_host_secret`,
//! `key_derivation`, `permutation`, `permutation_cache`, `wordlist`,
//! `mapping`, `crypto_compare`, `errors` — was carved out into
//! `v2-babbleon-scramble` (`babbleon_scramble_v2`) so a mobile fork can
//! reuse the math without this crate's Linux detection/response glue
//! (see `docs/v2/scramble-core-carve.md`).  This crate re-exports those
//! modules under their original `babbleon_core_v2::...` paths — so no
//! downstream consumer changed — and adds the Linux-welded layer on top:
//!
//! - **`events`** — `/proc`-aware event model with JSONL file sinks and
//!   an ed25519 audit-chain sink.
//! - **`tripwire`** — decoy-access detection and response policy.
//! - **`wrapper`** — emits the `/bin/sh` tripwire wrapper scripts.
//! - **`activated_table_bridge`** — builds a launch-artefact
//!   `ActivatedTable` from a scramble-engine `EpochMapping`.
//!
//! New code that needs only the scramble engine (the preprocessor, the
//! mobile fork) should depend on `v2-babbleon-scramble` directly.
//!
//! # Security baseline applied
//!
//! Every v2 crate satisfies (see `docs/v2/security-baseline.md`):
//!
//! - `#![forbid(unsafe_code)]` at the crate root.  This crate uses
//!   only safe Rust; any v2 crate that needs unsafe quarantines it to
//!   one syscall module.
//! - Secret-holding types wrap their bytes in `zeroize::Zeroizing`
//!   or `secrecy::SecretBox`.
//! - Secret-derived compares go through
//!   `crypto_compare::secret_bytes_equal` (constant-time).
//! - Domain separation uses HKDF, NOT hand-rolled hash-of-concat.
//! - Every public function / type / module has a name that reads as
//!   plain English (see `docs/v2/naming-conventions.md`).
//!
//! # Differential testing against v1
//!
//! `tests/v1_compat.rs` asserts that v2's identifier scramble
//! produces the same compound name as v1 for the same
//! `(host_secret, epoch, tool)` triple.  This is the go/no-go gate
//! for phase 1 — if v2's primitive doesn't match v1's, we have
//! introduced a regression in the only piece v1 reliably got right.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(clippy::pedantic)]
// Pedantic lints we explicitly relax — none yet; reconsider per file
// as the crate grows.

// The pure scramble engine was carved out into `v2-babbleon-scramble`
// (see `docs/v2/scramble-core-carve.md`) so a mobile fork can share it
// without pulling this crate's Linux detection/response glue.  Core is
// now a Linux-tier facade: it re-exports the pure modules under their
// old paths — so every `babbleon_core_v2::mapping::...`,
// `::key_derivation::...`, `::per_host_secret::...` call site (including
// this crate's own `wrapper`/`tripwire`/`activated_table_bridge`, which
// reference `crate::mapping` etc.) keeps resolving unchanged — and keeps
// the OS-welded modules as real modules.
pub use babbleon_scramble_v2::{
    crypto_compare, errors, key_derivation, mapping, per_host_secret,
    permutation, permutation_cache, wordlist,
};

pub mod activated_table_bridge;
pub mod events;
pub mod tripwire;
pub mod wrapper;

// The `activated_table` and `credentials` modules were extracted
// to `v2-babbleon-launch-artefacts` so the launcher and PAM can
// consume them without pulling in the crypto stack.  Core
// re-exports the same public surface so existing
// `babbleon_core_v2::ActivatedTable` / `babbleon_core_v2::discover_credential_dirs`
// call sites keep working.  New code should prefer the artefacts
// crate directly when it does not need core's primitives.
pub use activated_table_bridge::build_activated_table_from_mapping;
pub use babbleon_launch_artefacts_v2::{
    discover_credential_dirs, is_credential_env_var,
    scrub_credential_env_vars, ActivatedEntry, ActivatedTable,
    ActivatedTableBuilder, CREDENTIAL_DIRS_RELATIVE_TO_HOME,
    MAX_TABLE_BYTES, SCRUB_ENV_SUFFIXES, SCRUB_ENV_VAR_NAMES,
};
pub use errors::{Error, Result};
pub use events::{
    AuditChainSink, Event, EventSink, JsonlFileSink, Severity, StderrSink,
    TripwireSource,
};
pub use mapping::{EpochMapping, MappingBuilder, COMPOUND_N, HONEY_COUNT};
pub use per_host_secret::{PerHostSecret, PER_HOST_SECRET_LEN};
pub use permutation::Permutation;
pub use permutation_cache::{PermutationCache, DEFAULT_CAPACITY as PERMUTATION_CACHE_DEFAULT_CAPACITY};
pub use tripwire::{TripwireResponder, TripwireResponsePolicy};
pub use wordlist::Wordlist;
pub use wrapper::{
    write_all_tripwire_wrappers, write_all_wrappers, write_honey_list,
    write_stale_list, write_tripwire_wrapper, write_wrapper,
    TRIPWIRE_EVENTS_FIFO, TRIPWIRE_HONEY_LIST, TRIPWIRE_STALE_LIST,
};
