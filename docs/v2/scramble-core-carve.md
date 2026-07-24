# Plan — carve the scramble engine out of `v2-babbleon-core`

Extract the OS-agnostic scramble/mapping primitives out of
`v2-babbleon-core` into a new pure crate, leaving `v2-babbleon-core`
as a Linux-tier facade over it.  This unblocks a mobile Babbleon
(Android/enterprise) fork that shares the scramble engine but rebuilds
enforcement, without disturbing the existing Linux code paths.

Additive by design: nothing on the Linux side is deleted, and the
public surface of `babbleon_core_v2` is preserved byte-for-byte, so no
downstream consumer needs editing.

## Why now

`v2-babbleon-core` currently fuses two things the dependency graph
already keeps separate:

- the **scramble engine** — pure computation (HKDF sub-keys, bijective
  permutations, the per-epoch name table).  No syscalls, no paths.
- the **Linux detection/response layer** — `wrapper` (emits a
  `/bin/sh` tripwire wrapper referencing `/proc/self/ns/mnt`, `stat`,
  `grep`), `tripwire` and `events` (`/proc/<pid>/stat` start-time
  semantics, JSONL file sinks, audit-chain signing).

A mobile port needs the first and none of the second (Android has no
PAM, no login shell, mandatory SELinux instead of composable LSMs, a
zygote/app model instead of fork-exec).  Separating them is also good
hygiene on the Linux side: it isolates the crypto an auditor most wants
to read from the syscall glue around it.

## Audit — the split is clean

The intra-crate dependency graph splits along a fault line with no
cycles.  All dependencies from the Linux-welded modules point *down*
into the pure ones; no pure module imports a Linux-welded one.

```
PURE (closed under deps)                 LINUX-WELDED (stays in facade)
  errors            (leaf)                 events         (/proc, std::fs JSONL, ed25519 audit-chain)
  crypto_compare    (leaf)                 tripwire       -> events
  per_host_secret   -> errors              wrapper        -> key_derivation, per_host_secret  (emits /bin/sh)
  key_derivation    -> errors, per_host_secret          activated_table_bridge -> mapping, errors, launch-artefacts
  wordlist          -> errors
  permutation       -> errors, key_derivation, per_host_secret
  permutation_cache -> permutation
  mapping           -> errors, per_host_secret, permutation, permutation_cache, wordlist
```

Two facts that make the carve zero-churn for consumers:

1. **Downstream imports use module paths** — e.g.
   `babbleon_core_v2::per_host_secret::PerHostSecret`,
   `::mapping::COMPOUND_N`, `::key_derivation::derive_subkey`,
   `::permutation::Permutation`, `::wordlist::Wordlist`.  So the facade
   must re-export *modules*, not just flat names.  It does (below).
2. **The preprocessor only ever reaches pure modules** — never
   `events`/`tripwire`/`wrapper`.  This is the empirical proof that the
   scramble engine is genuinely shareable with a mobile fork, and it
   means the preprocessor can later depend on the new crate directly.

## Target topology (facade — recommended over an immediate rename)

```
        v2-babbleon-scramble   (NEW, pure Rust, forbid(unsafe))
          errors  crypto_compare  per_host_secret  key_derivation
          permutation  permutation_cache  wordlist  mapping
          lib name: babbleon_scramble_v2
                    |                         |
   desktop (unchanged)                        |  mobile fork + preprocessor
                    v                         v
   v2-babbleon-core (Linux facade)      mobile-babbleon (later)
     events  tripwire  wrapper            SELinux policy, system-service,
     activated_table_bridge               binder/property interception,
     + pub use babbleon_scramble_v2::*    its own tripwire impl;
                                          depends on scramble only
```

`v2-babbleon-core` keeps the detection/response modules and re-exports
the pure surface, so every existing `babbleon_core_v2::...` call site
keeps compiling.  A mobile crate depends on `v2-babbleon-scramble`
directly and never pulls the facade.

## Status

- **Steps 1–3 landed** in `5fa6bd7` (carve + facade + workspace member).
- **Step 4 landed** in `134e0b3` (preprocessor repointed onto
  `v2-babbleon-scramble`).
- **Verification gate — NOT yet run.**  This host has no Rust
  toolchain, so `cargo build`/`cargo test` (below) could not be
  executed.  The changes are mechanical (git-tracked renames + a
  re-export facade + a uniform import rename) and were grep-verified —
  every `crate::` reference in the moved set targets one of the eight
  moved modules, every re-exported symbol exists, and zero
  `babbleon_core_v2` references remain in the preprocessor — but the
  carve is not "done" until the gate is green on a real build host.
- Deferred items below (events/tripwire/wrapper relocation, core rename,
  vault path abstraction) remain unstarted.

## Steps

### 1. Create `crates/v2-babbleon-scramble`

Move these eight files verbatim from `crates/v2-babbleon-core/src/`
into `crates/v2-babbleon-scramble/src/` (they move as a set, so their
internal `use crate::...` lines stay valid):

```
errors.rs  crypto_compare.rs  per_host_secret.rs  key_derivation.rs
wordlist.rs  permutation.rs  permutation_cache.rs  mapping.rs
```

`Cargo.toml`:

```toml
[package]
name = "v2-babbleon-scramble"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true
repository.workspace = true

[lib]
name = "babbleon_scramble_v2"

[dependencies]
hkdf = { workspace = true }
hmac = { workspace = true }
sha2 = { workspace = true }
rand = { workspace = true }
rand_chacha = { workspace = true }
hex = { workspace = true }
zeroize = { workspace = true }
subtle = { workspace = true }
thiserror = { workspace = true }
tracing = { workspace = true }
once_cell = { workspace = true }
serde = { workspace = true }   # verify EpochMapping/Wordlist actually derive; trim if not
```

Deliberately absent (they belong to `events`/`activated_table_bridge`,
which stay in the facade): `serde_json`, `ed25519-dalek`,
`v2-babbleon-launch-artefacts`.

`lib.rs` for the new crate carries `#![forbid(unsafe_code)]` and
`#![deny(missing_docs)]` (all moved modules are already safe Rust) and
`pub mod` for the eight modules.

### 2. Turn `v2-babbleon-core/src/lib.rs` into the facade

Replace the eight pure `pub mod` declarations with module re-exports;
keep the four Linux modules as real modules; repoint the flat
re-exports at the scramble crate:

```rust
// pure surface, re-exported so `babbleon_core_v2::mapping::...` still resolves
pub use babbleon_scramble_v2::{
    crypto_compare, errors, key_derivation, mapping,
    per_host_secret, permutation, permutation_cache, wordlist,
};

pub mod events;
pub mod tripwire;
pub mod wrapper;
pub mod activated_table_bridge;

pub use errors::{Error, Result};
pub use mapping::{EpochMapping, MappingBuilder, COMPOUND_N, HONEY_COUNT};
pub use per_host_secret::{PerHostSecret, PER_HOST_SECRET_LEN};
pub use permutation::Permutation;
pub use permutation_cache::{PermutationCache, DEFAULT_CAPACITY as PERMUTATION_CACHE_DEFAULT_CAPACITY};
pub use wordlist::Wordlist;
// events / tripwire / wrapper / activated_table_bridge flat re-exports unchanged
```

Because the facade re-exports the moved modules under their old names,
`crate::key_derivation`, `crate::mapping`, `crate::errors`, etc. still
resolve inside `wrapper.rs`, `tripwire.rs`, and
`activated_table_bridge.rs` — those files need **no edits**.

Add the dependency to `crates/v2-babbleon-core/Cargo.toml`:

```toml
v2-babbleon-scramble = { path = "../v2-babbleon-scramble" }
```

### 3. Register the crate

Add `"crates/v2-babbleon-scramble",` to the workspace `members` list in
the root `Cargo.toml`.

### 4. (Follow-up, recommended) repoint the preprocessor

Change `v2-babbleon-preprocessor` to depend on `v2-babbleon-scramble`
and rewrite its ~10 `babbleon_core_v2::` imports to
`babbleon_scramble_v2::`.  Not required for correctness — the facade
already covers it — but it severs the preprocessor's needless
dependency on the Linux facade and is the exact shape the mobile fork
will consume.  Do it as a separate commit once the split is green.

## Churn

| Change | Count |
| --- | --- |
| Files moved (unedited) | 8 |
| New `Cargo.toml` + `lib.rs` | 2 |
| Edits to `core` (`lib.rs`, `Cargo.toml`) | 2 |
| Workspace member line | 1 |
| Downstream consumer edits | 0 |

daemon, launch-untrusted, python-shim, resilience-bench, v2-babbleon,
and `tools/*` all compile unchanged.

## Verification gate (must pass before merge)

Cannot be run on a host without a Rust toolchain; this plan is not
"done" until it is green on a real build host.

1. `cargo build --workspace` — green.
2. `cargo test -p v2-babbleon-core --test v1_compat` — still green.
   This is the go/no-go gate that v2's scramble matches v1 for the same
   `(host_secret, epoch, tool)` triple; the carve must not perturb it.
3. `cargo test -p v2-babbleon-preprocessor` — round-trip proptests green.
4. `#![forbid(unsafe_code)]` holds in `v2-babbleon-scramble`.

## Deliberately deferred (separate carves)

- **Relocate `events`/`tripwire`/`wrapper` into a dedicated
  `linux-babbleon` response crate.**  Not needed to unblock mobile —
  mobile simply won't depend on the facade.  Hygiene, do it later.
- **Rename `v2-babbleon-core`** to something that reflects it is now a
  Linux facade, not "core."  Cosmetic; repoints ~10 import sites.  Do
  it after the split lands green, if at all.
- **Vault path abstraction** (`/etc/babbleon/vault.age`, XDG,
  `#[cfg(unix)]` perms behind a platform-path trait).  Independent; do
  it when a mobile vault backend actually needs it.
