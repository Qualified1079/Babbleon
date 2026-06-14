# RUST_PLAN.md — Babbleon Rust Rewrite

Companion to PLAN.md. PLAN.md is the architecture; this document is the
language/tooling realization.

## Why Rust

1. Memory safety in privileged code paths (setuid helper, PAM module).
2. Single language across community + commercial codebases.
3. Static single-binary distribution; no interpreter on production hosts.
4. Smaller, more auditable surface than Python + pip dep tree.
5. Native crates exist for every component (age, argon2, nix, tss-esapi, libbpf-rs, landlock).
6. Compile-time platform gating via `cfg` attributes — no runtime stub work.

## Workspace layout

    babbleon/
    ├── Cargo.toml              # workspace
    ├── Cargo.lock
    ├── crates/
    │   ├── babbleon/                  # library — all the core types
    │   │   └── src/
    │   │       ├── lib.rs
    │   │       ├── errors.rs
    │   │       ├── platform.rs
    │   │       ├── mapping/           # fpe, mapper, wordlist
    │   │       ├── vault/             # core + backends
    │   │       ├── enforcement/       # driver, simulated, linux_ns, wrapper
    │   │       ├── session.rs
    │   │       ├── events.rs
    │   │       ├── plugins.rs         # dynamic-loaded enterprise extensions
    │   │       ├── manifest.rs
    │   │       └── storage.rs
    │   ├── babbleon-cli/              # binary: `babbleon`
    │   │   └── src/main.rs
    │   └── babbleon-ns-helper/        # binary: setuid helper (M3)
    │       └── src/main.rs            # tiny, audited, drops caps immediately
    └── tests/                          # integration tests

## Crate selection

| Concern | Crate | Notes |
|---|---|---|
| Vault encryption | `age` | rage upstream; supports passphrase + identity |
| Password KDF | `argon2` | RustCrypto; Argon2id m=46MiB/t=2/p=1 |
| HMAC + SHA-256 | `hmac`, `sha2` | RustCrypto; for FPE round function |
| CSPRNG | `rand`, `rand_chacha` | seeded permutations via ChaCha20 |
| Linux syscalls | `nix` | unshare, mount, umount2 — no ctypes equivalent |
| Landlock LSM | `landlock` | first-class crate; v3 ABI |
| TPM2 | `tss-esapi` | native ESAPI bindings; replaces tpm2-tools subprocess |
| FIDO2 | `authenticator` (Mozilla) | CTAP2 hmac-secret extension |
| eBPF-LSM | `libbpf-rs` + `aya` | aya is pure Rust; libbpf-rs is mature |
| CLI | `clap` (derive) | standard |
| Serialization | `serde`, `serde_json`, `toml` | manifest + vault payload + state |
| Errors | `thiserror`, `anyhow` | thiserror in lib, anyhow in bin |
| Tracing | `tracing`, `tracing-subscriber` | structured logs for EventBus |
| Tests | built-in + `tempfile`, `assert_cmd`, `predicates` | |
| Lint | `clippy`, `cargo-deny`, `cargo-audit` | enterprise audit story |

## Platform gating

- `#[cfg(target_os = "linux")]` on the entire `enforcement::linux_ns` module
  and the helper binary's body. macOS / Windows ports come in later milestones.
- Feature flags:
  - `tpm` → pulls `tss-esapi`
  - `fido2` → pulls `authenticator`
  - `landlock` → pulls `landlock` crate
  - `ebpf` → pulls `aya`
  - default: `tpm` + `fido2` on Linux; nothing on macOS until M5.

## Hardware abstraction

`enforcement::driver::EnforcementDriver` trait + factory pattern (mirrors the
Python design). `vault::backend::KekBackend` trait. Both are object-safe so
enterprise extensions can ship trait-object implementations behind a `Box<dyn>`.

Hardware crates (TPM, FIDO2) are never imported in trait code — only in the
concrete backend modules. Builds without `--features tpm,fido2` work on any
host.

## Enterprise extension model

Rust doesn't have Python-style entry_points. Two options, both supported:

1. **Compile-time:** enterprise depends on `babbleon` crate, implements the
   traits, ships its own `babbleon-enterprise` binary that wraps the public
   `babbleon` CLI's logic. Simpler; ships static.
2. **Runtime:** dynamic library plugins loaded via `libloading`. Slot in via
   a registered factory function. More flexible; needs an unsafe boundary.

Default to (1) for now; (2) is DEFERRED.

## Component-by-component plan

### Phase 1: core library scaffolding (≤30 min)
- Workspace + babbleon library crate + babbleon-cli binary crate
- `errors.rs`: thiserror enum mirroring Python errors
- `platform.rs`: cfg-based detection helpers
- `manifest.rs`: default tracked list + toml loader

### Phase 2: mapping (≤45 min)
- `mapping::fpe`: seeded Fisher-Yates permutation via ChaCha20Rng
  (replaces the broken Python Feistel; same correctness guarantees)
- `mapping::mapper`: build_table + honey + scramble/reveal
- Wordlist embedded as `include_str!` from `wordlist/words.txt`
- Tests: bijectivity, epoch independence, no collisions

### Phase 3: vault (≤60 min)
- `vault::core`: VaultPayload (serde) + Vault struct
- `vault::backend`: KekBackend trait
- `vault::soft`: Argon2id → age passphrase
- `vault::usb`: keyfile (+ optional 2FA)
- `vault::factory`: best_available + for_tier
- TPM/FIDO2: skeleton modules behind features (DEFERRED bodies)
- Tests: seal/unseal roundtrip, wrong passphrase, USB roundtrip

### Phase 4: session + events + storage (≤30 min)
- `session::Session`: init/unlock/rotate
- `events::EventBus`: trait-object sinks
- `storage`: XDG paths

### Phase 5: enforcement (≤45 min)
- `enforcement::driver` trait
- `enforcement::simulated`
- `enforcement::linux_ns` (cfg-gated)
- `enforcement::wrapper`: generates wrapper scripts; production
  M3.5 version will be a real Rust binary instead
- `enforcement::factory`

### Phase 6: CLI (≤30 min)
- clap derive: init, unlock, rotate, trusted, untrusted, status, sim
- Reads passphrase via `rpassword`

### Phase 7: attacker sim + demo (≤30 min)
- Built into the CLI as `babbleon demo` subcommand (no separate sandbox dir)

### Phase 8: ns-helper skeleton (≤30 min, M3 prep)
- Tiny binary; cfg-gated to Linux
- Does unshare + drop privs + execvp into untrusted shell
- Body is DEFERRED until the full M3 push; skeleton only

## What gets deleted from the Python codebase

- `babbleon/` package
- `sandbox/` directory
- `tests/` directory
- `pyproject.toml`

## What gets kept

- `README.md` (rewritten for Rust install)
- `PLAN.md`, `RESEARCH.md`, `DEFERRED.md`, `RUST_PLAN.md`
- `.gitignore` (updated for Rust artifacts)

## Acceptance criteria (Rust M1)

- `cargo build --release` produces a single `babbleon` binary on Linux/macOS
- `cargo test` passes on a host with no TPM/FIDO2 hardware
- `babbleon demo` runs end-to-end: init vault → show views → attacker sim
  (0/14 hits) → rotate → re-sim → honey-tripwire fires
- `cargo deny check` and `cargo clippy -- -D warnings` clean
- No `unsafe` outside `_syscalls` modules and the FFI boundary helpers

## Out of scope for this rewrite session

Same DEFERRED.md items as before — Rust doesn't change which items are
deferred, only the language they'll eventually be written in. Specifically
DEFERRED in the rewrite:

- pam_babbleon.so (still C, needed for PAM ABI)
- ns-helper full body (skeleton only this session)
- TPM/FIDO2 backend bodies (skeleton + feature gate this session)
- eBPF-LSM hooks (DEFERRED M3)
- Landlock self-sandbox (DEFERRED M3, easy in Rust with `landlock` crate)
- Banner-spoofing wrapper as real binary (DEFERRED M3.5)
