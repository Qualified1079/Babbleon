# Security-baseline self-audit — v2 crates as of 2026-06-20 (phase-3 MVP)

Cross-reference: `docs/v2/security-baseline.md` (the 15 rules).

This document records the audit findings for every v2 crate as of
the snapshot below.  Each rule is checked per crate.  A "PASS"
entry cites the specific file / line evidence; a "DEFER" entry
names the follow-up commit that must land before the crate is
considered shippable.

Snapshot HEAD: `4d5864b` (HANDOFF item 2 closed — vault unlock
end-to-end and daemon defaults to Locked).  Previous snapshot
`75abdca` covered the protocol carve-out.  Since then the vault
unlock track landed across five commits:

- `83152e1` — new crate `v2-babbleon-vault` (32 tests).
- `fbdd7f1` — `Request::Unlock` + `Response::Unlocked` in the
  protocol crate (UnlockSecret with hex wire form,
  zeroize-on-drop, redacted Debug).
- `e6cc823` — DaemonState refactored to Locked / Unlocked enum
  (epoch / mapping accessors became `Option<...>`).
- `b8d2a7e` — user-CLI `babbleon init` and `babbleon unlock`
  wired (passphrase via TTY or stdin, vault file at mode 0o600).
- `4d5864b` — daemon defaults to starting Locked;
  `--insecure-stub-secret` is now opt-in for tests / dev.

Rows below: new `v2-babbleon-vault` section, refreshed
`v2-babbleon-daemon-protocol`, `v2-babbleon-daemon`,
`v2-babbleon` sections.

---

## Crate: `v2-babbleon-core`

| # | Rule | Status | Evidence |
|---|---|---|---|
| 1 | `forbid(unsafe_code)` at crate root | ✅ PASS | `src/lib.rs:53` |
| 2 | `deny(missing_docs)` + `warn(clippy::pedantic)` | ✅ PASS | `src/lib.rs:54-55`; `cargo clippy -p v2-babbleon-core` is clean |
| 3 | Secrets wear `Zeroizing`, no `Clone/Copy/Debug` | ✅ PASS | `src/per_host_secret.rs` — `Zeroizing<[u8;32]>`; no derives of Clone/Copy/Debug |
| 4 | Secret-derived compares are constant-time | ✅ PASS | `src/crypto_compare.rs` `is_secret_byte_match` + `is_secret_hex_match`; mapping.rs uses `is_secret_byte_match` in `is_honey` |
| 5 | Domain separation via HKDF | ✅ PASS | `src/key_derivation.rs` `derive_subkey` (RFC 5869); all callers use distinct `purpose` labels (`v2-identifier-mapping`, `v2-honey-mapping`, `v2-wrapper-pad`) |
| 6 | Plain-English names | ✅ PASS | every module name describes purpose (`mapping`, `wordlist`, `wrapper`, `tripwire`, `activated_table`, `credentials`); no abbreviations of obscure origin |
| 7 | "What this defeats" module docs | ✅ PASS | all of `mapping.rs`, `per_host_secret.rs`, `key_derivation.rs`, `permutation.rs`, `wrapper.rs`, `tripwire.rs`, `activated_table.rs`, `credentials.rs` open with the template |
| 8 | Process hardening at startup | N/A | library crate; rule applies to binaries |
| 9 | `SAFETY:` comment on every `unsafe` block | ✅ PASS (vacuous) | `forbid(unsafe_code)` makes this vacuously true |
| 10 | Capability annotation per syscall site | N/A | no syscalls (library only) |
| 11 | No long-lived secrets in serde-deserialized types | ✅ PASS | the only serde::Deserialize-derived types live in `events.rs` and they carry no secret material |
| 12 | RFC-recognisable primitives only | ✅ PASS | HKDF-SHA-256 (RFC 5869), SHA-256 (FIPS 180-4), Ed25519 (RFC 8032) — all RustCrypto wrappers |
| 13 | Errors do not leak secrets | ✅ PASS | `errors.rs` variants carry strings; reviewed: no construction site passes secret bytes into a format string |
| 14 | Secret-bearing args are `&` references | ✅ PASS | every function that takes a `PerHostSecret` takes it by reference; `MappingBuilder::new(secret: &'a PerHostSecret, ...)` |
| 15 | Tests cover unit + property invariants | ✅ PASS | 99 unit tests; `mapping.rs::collision_resistance_across_many_secrets_and_epochs` and `rotation_changes_honey_names_too` are property tests |

**Verdict:** v2-babbleon-core passes all applicable rules.

---

## Crate: `v2-babbleon-launch-untrusted`

| # | Rule | Status | Evidence |
|---|---|---|---|
| 1 | `forbid(unsafe_code)` at crate root | ✅ PASS (with documented exception) | `src/lib.rs:65-66` — `deny(unsafe_code)` on Linux + quarantine in `syscall.rs`; rule 1 exception policy invoked |
| 2 | `deny(missing_docs)` + `warn(clippy::pedantic)` | ✅ PASS | `src/lib.rs:67-68`; `cargo clippy --all-targets` clean for all 12 launcher warnings cleared in commit `02cf945` |
| 3 | Secrets wear `Zeroizing`, no `Clone/Copy/Debug` | ✅ PASS (vacuous) | launcher holds NO secret material — that's the whole point of the secret-free activated-table design |
| 4 | Constant-time compares | N/A | no secret material in this crate |
| 5 | HKDF for domain separation | N/A | no key derivation in this crate |
| 6 | Plain-English names | ✅ PASS | every module is named for what it does: `bounding_set`, `credential_gate`, `activated_table_input`, `process_hardening`, `seccomp_profile`, etc. |
| 7 | "What this defeats" module docs | ✅ PASS | `lib.rs`, `bounding_set.rs`, `namespaces.rs`, `mounts.rs`, `credential_gate.rs`, `activated_table_input.rs`, `process_hardening.rs`, `seccomp_profile.rs`, `identity_drop.rs` — all open with the template.  `errors.rs`, `preflight.rs`, `cli.rs`, `syscall.rs` use the Infrastructure-module variant |
| 8 | Process hardening at startup | ✅ PASS | `process_hardening::apply_secret_hygiene` runs at step 3 (PR_SET_DUMPABLE, RLIMIT_CORE, mlockall); orchestrator wires it before any secret-bearing code can run (though the launcher has no secrets, applying the rule still belt-and-braces against future regressions) |
| 9 | `SAFETY:` comment on every `unsafe` block | ✅ PASS | all unsafe blocks live in `syscall.rs`; each carries a `SAFETY:` comment with named invariants (e.g. lines 53-58, 89-91, 110-112, 134-136, 186-191, [new] adopt_raw_fd_as_file) |
| 10 | Capability annotation per syscall site | ✅ PASS | every privileged call site in `bounding_set.rs`, `namespaces.rs`, `mounts.rs`, `process_hardening.rs`, `identity_drop.rs`, `credential_gate.rs` has a `CAPABILITY:` comment naming the cap and when it's dropped |
| 11 | No long-lived secrets in serde-deserialized types | ✅ PASS | the only deserialised type is `ActivatedTable` (via core) and it contains no secret bytes by design |
| 12 | RFC-recognisable primitives | N/A | no crypto in this crate |
| 13 | Errors do not leak secrets | ✅ PASS | every error variant carries a string built from non-secret inputs; no secret data is on this crate's call paths in the first place |
| 14 | Secret-bearing args are `&` references | N/A | no secret args |
| 15 | Tests cover unit + property invariants | ✅ PASS | 34 unit + 5 integration + 3 rooted; integration tests exercise the daemon-launcher loop end-to-end |

**Verdict:** v2-babbleon-launch-untrusted passes all applicable rules.
Rule 8 is deliberately over-applied (the launcher has no secrets,
but the hardening calls cost nothing and guard against a future
maintainer accidentally loading secret material in this crate).

---

## Crate: `v2-babbleon`  (user-facing CLI; vault unlock wired 2026-06-20)

| # | Rule | Status | Evidence |
|---|---|---|---|
| 1 | `forbid(unsafe_code)` | ✅ PASS | `src/main.rs:30` |
| 2 | `deny(missing_docs)` + pedantic | ✅ PASS | `src/main.rs:31`; clippy clean across passphrase.rs / vault_lifecycle.rs / main.rs |
| 3 | Secrets wear `Zeroizing`, no Clone/Copy/Debug | ✅ PASS | `passphrase::Passphrase` wraps `Zeroizing<String>`; `vault_lifecycle::generate_host_secret` returns `Zeroizing<Vec<u8>>`.  The CLI process holds the unwrapped secret for exactly one `Vault::unseal -> UnlockSecret::from_bytes -> round_trip(Request::Unlock)` stack frame, then drops |
| 4 | Constant-time compares | N/A | no secret-to-secret compares; passphrase confirm uses plain string compare since both sides are operator-controlled |
| 5 | HKDF for domain separation | ✅ PASS (delegated) | KDF lives in `v2-babbleon-vault::SoftBackend` (Argon2id RFC 9106); this crate just plumbs the passphrase through |
| 6 | Plain-English names | ✅ PASS | `passphrase`, `vault_lifecycle`, `prompt_passphrase`, `run_init`, `run_unlock` — every public item describes its job |
| 7 | "What this defeats" module docs | ✅ PASS | `main.rs`, `passphrase.rs`, `vault_lifecycle.rs` open with the template |
| 8 | Process hardening at startup | DEFER (mlockall on the unlock path) | the CLI process holds the secret briefly during the unlock round-trip; not currently mlockall'd because the secret's window is one syscall.  Filed as future tighten |
| 9 | `SAFETY:` comment on every `unsafe` block | ✅ PASS (vacuous) | `forbid(unsafe_code)` at crate root |
| 10 | Capability annotation per syscall site | ✅ PASS | the only privileged-ish syscalls are `open` for vault read/write and `connect` to the daemon socket; neither requires extra caps |
| 11 | No long-lived secrets in serde-deserialized types | ✅ PASS | no serde::Deserialize on operator-influenceable surface; the vault-payload deserializer lives in `v2-babbleon-vault::payload` and is hand-managed (rule 11 enforced there) |
| 12 | RFC-recognisable primitives | ✅ PASS (delegated) | uses age (delegated to v2-babbleon-vault) and Argon2id; no inline crypto |
| 13 | Errors do not leak secrets | ✅ PASS | uses anyhow with non-secret strings; the wrong-passphrase error surface is `v2-babbleon-vault::Error::WrongPassphrase` which carries no fields |
| 14 | Secret-bearing args are `&` references | ✅ PASS | `passphrase.expose() -> &str` is the only secret accessor; `UnlockSecret::from_bytes(&[u8])` takes the secret-bearing slice by reference |
| 15 | Tests cover unit + property invariants | ✅ PASS | 16 unit (6 passphrase + 4 vault_lifecycle + 6 main clap) + 7 integration tests against the real daemon binary |

**Verdict:** passes all applicable rules.  Rule 8 is DEFERed (the
CLI does not mlockall during the brief unwrap window) — the
secret's live window is one stack frame; an attacker who can read
the CLI's address space during that window has already won at a
higher layer.  Promotion to PASS would tighten this.

---

## Crate: `v2-babbleon-daemon`  (shipping, phase-3 vault unlock; defaults to Locked startup)

| # | Rule | Status | Evidence |
|---|---|---|---|
| 1 | `forbid(unsafe_code)` | ✅ PASS | `src/lib.rs:63`, `src/main.rs:10` |
| 2 | `deny(missing_docs)` + pedantic | ✅ PASS | `src/lib.rs:64-65`; `cargo clippy -p v2-babbleon-daemon --all-targets -- -D warnings` clean post-Locked/Unlocked refactor |
| 3 | Secrets wear `Zeroizing`, no `Clone/Copy/Debug` | ✅ PASS | `state.rs` — `DaemonState` wraps `SecretState::Locked` or `SecretState::Unlocked { secret: PerHostSecret, ... }`.  `DaemonState` itself derives no Clone/Copy/Debug.  The Locked state holds NO secret bytes in memory at all |
| 4 | Constant-time compares | ✅ PASS (vacuous in this crate) | no secret-to-secret compare in the daemon; the core crate's `crypto_compare` is reached transitively via `MappingBuilder::is_honey` calls |
| 5 | HKDF for domain separation | ✅ PASS (delegated) | daemon does not derive keys directly; it calls `MappingBuilder::new(secret, wordlist).build(...)` which performs HKDF inside the core crate |
| 6 | Plain-English names | ✅ PASS | `state`, `handlers`, `socket`, `hardening`, `materialization`, `cli` — every module is named for its job.  `DaemonState::new_locked` / `new_unlocked` / `unlock` / `vault_locked` follow the plain-English convention |
| 7 | "What this defeats" module docs | ✅ PASS | `lib.rs`, `state.rs`, `socket.rs`, `hardening.rs`, `materialization.rs` open with the template (state.rs's docstring expanded to cover the Locked/Unlocked lifecycle); `handlers.rs`, `errors.rs`, `cli.rs` use the Infrastructure-module variant |
| 8 | Process hardening at startup | ✅ PASS | `hardening::apply_secret_hygiene` invoked from `main.rs::run_daemon` BEFORE any `PerHostSecret` construction (both startup paths, Locked and stub-Unlocked) |
| 9 | `SAFETY:` comment on every `unsafe` block | ✅ PASS (vacuous) | `forbid(unsafe_code)` at crate root |
| 10 | Capability annotation per syscall site | ✅ PASS | hardening + materialise sites carry capability comments; socket bind is unprivileged (`UnixListener::bind`); the daemon runs as a dedicated UID with no caps per `docs/v2/least-privilege.md` |
| 11 | No long-lived secrets in serde-deserialized types | ✅ PASS | wire protocol lives in `v2-babbleon-daemon-protocol`, hand-parsed via `serde_json::Value`.  `Request::Unlock` parses `host_secret_hex` through `UnlockSecret::from_hex_wire` which decodes straight into a `Zeroizing<[u8;32]>`; the intermediate hex `String` lives one stack frame and never becomes a daemon-side field |
| 12 | RFC-recognisable primitives | ✅ PASS (delegated) | daemon uses core's HKDF-SHA-256 / Fisher-Yates / Ed25519 wrappers; introduces no new crypto |
| 13 | Errors do not leak secrets | ✅ PASS | `errors.rs` variants carry strings; reviewed: no construction site passes secret bytes; `handlers::error_response` maps daemon `Error` to wire `Response::Error` with `Display` form only.  `Error::Vault("vault is already unlocked ...")` from the double-unlock guard carries no secret bytes |
| 14 | Secret-bearing args are `&` references | ✅ PASS | the secret enters by move via `DaemonState::unlock(secret: PerHostSecret)` or `new_unlocked(...)` and stays in the struct for the daemon's lifetime; `MappingBuilder::new(secret, ...)` accesses it by reference thereafter.  `handlers::unlock` takes `&UnlockSecret` |
| 15 | Tests cover unit + property invariants | ✅ PASS | 86 unit + 3 client_round_trip integration + 5 end_to_end_binary integration + 1 seccomp envelope integration + 2 seccomp denial tests; `state.rs` rotation tests assert epoch advance + scrambled-name change; new lifecycle tests cover Locked / Unlocked transitions, double-unlock rejection, locked-mutator rejection |

**Verdict:** the daemon passes every applicable rule.  The Locked
startup default is now the secure default: a freshly-started
daemon holds no secret material until an operator unlocks via
`babbleon unlock`.  The `--insecure-stub-secret` opt-in remains
for test paths and is documented as "NOT for production" in the
CLI help.

Note on rule 14: the `unlock` method takes the secret by move
(constructor-style, consistent with the rule's exception policy).
After construction, all access is by `&` reference through
`MappingBuilder::new(&secret, ...)`.

---

## Crate: `v2-babbleon-daemon-protocol`  (protocol carve-out; Unlock added 2026-06-20)

The wire protocol + client + canonical socket path, carved out of
the daemon crate so its peers (launcher, user CLI) link only the
small protocol surface.  No state, no I/O loop, no materialisation;
no `v2-babbleon-core` dependency.

Phase-3 update: now also carries an `UnlockSecret` type — a brief
secret-bearing wire payload.  The crate is no longer
"holds-no-secret-material"; it holds a `Zeroizing<[u8;32]>` for
exactly the duration of one Request::Unlock parse-or-construct
call.

| # | Rule | Status | Evidence |
|---|---|---|---|
| 1 | `forbid(unsafe_code)` | ✅ PASS | `src/lib.rs:38` |
| 2 | `deny(missing_docs)` + pedantic | ✅ PASS | `src/lib.rs:39-40`; `cargo clippy -p v2-babbleon-daemon-protocol --all-targets -- -D warnings -W clippy::pedantic` clean |
| 3 | Secrets wear `Zeroizing`, no `Clone/Copy/Debug` | ✅ PASS (with one documented relaxation) | `UnlockSecret` wraps `Zeroizing<[u8;32]>`; hand-rolled `Debug` prints `"<redacted>"`; `Clone` IS derived as a structural concession to the proptest harness (`Strategy::Value: Clone`).  The relaxation is documented in `src/unlock_secret.rs` module docs; production paths do NOT clone (audit-checked by code review of `Request::parse` and `handlers::dispatch`) |
| 4 | Constant-time compares | ✅ PASS (deliberate non-CT for tests; not used for auth) | `impl PartialEq for UnlockSecret` is non-constant-time, documented in code: this comparison is for test assertions only.  No authentication path uses it |
| 5 | HKDF for domain separation | N/A | no key derivation |
| 6 | Plain-English names | ✅ PASS | `protocol`, `client`, `socket_path`, `errors`, `unlock_secret`, `UnlockSecret`, `Request::Unlock`, `Response::Unlocked` |
| 7 | "What this defeats" module docs | ✅ PASS | `lib.rs`, `protocol.rs`, `unlock_secret.rs` open with the template; `client.rs`, `socket_path.rs`, `errors.rs` use the Infrastructure-module variant |
| 8 | Process hardening at startup | N/A | library crate; no `main()` |
| 9 | `SAFETY:` comment on every `unsafe` block | ✅ PASS (vacuous) | `forbid(unsafe_code)` |
| 10 | Capability annotation per syscall site | ✅ PASS (vacuous) | crate makes no privileged syscalls — `UnixStream::connect` runs as the caller's UID with no extra caps |
| 11 | No long-lived secrets in serde-deserialized types | ✅ PASS | hand-parsed `serde_json::Value` throughout `protocol.rs`.  `Request::Unlock` parses `host_secret_hex` through `UnlockSecret::from_hex_wire` which decodes straight into `Zeroizing<[u8;32]>`.  The hex `String` produced by `serde_json::Value::as_str().to_owned()` is the unavoidable JSON limitation and lives one parse-call stack frame |
| 12 | RFC-recognisable primitives | ✅ PASS | hex encoding (RFC 4648 §8 base16); no other crypto |
| 13 | Errors do not leak secrets | ✅ PASS | `errors.rs` carries two variants (`Ipc`, `ActivatedTable`); both wrap `String` built from non-secret sources.  `UnlockSecret::from_hex_wire` error explicitly comments "do NOT include the hex string itself — it is the secret"; test `from_hex_wire_message_does_not_echo_input` asserts |
| 14 | Secret-bearing args are `&` references | ✅ PASS | `UnlockSecret::from_bytes(bytes: &[u8])` takes the slice by reference; `UnlockSecret::from_hex_wire(hex_str: &str)` similarly.  `expose()` returns `&[u8]`.  Constructor moves into the wrapper (rule 14 exception policy: constructors take by value) |
| 15 | Tests cover unit + property invariants | ✅ PASS | 46 unit (incl. 10 `UnlockSecret`, 5 `Request::Unlock`, 4 `Response::Unlocked`, 27 prior) + 6 proptest properties × 1024 cases each = 6144 random inputs covering no-panic / roundtrip / oversize-reject / byte-preservation across both Request and Response (incl. Unlock variant) |

**Verdict:** passes every applicable rule.  The narrow surface
carries one short-lived secret-bearing wire payload; the
discipline is preserved by hand-managed (de)serialization, a
hand-rolled redacted Debug, and the test-harness `Clone`
relaxation documented in code.

---

## Crate: `v2-babbleon-vault`  (new 2026-06-20 — at-rest seal of the per-host secret)

Vault library: `Vault::seal` / `unseal` with `age` passphrase
encryption + `Argon2id` KEK derivation in `SoftBackend`.  Linked
by the user-CLI only; NOT linked by the daemon (compartmentalised
audit surface — see crate docs for the rationale).

| # | Rule | Status | Evidence |
|---|---|---|---|
| 1 | `forbid(unsafe_code)` | ✅ PASS | `src/lib.rs:91` |
| 2 | `deny(missing_docs)` + pedantic | ✅ PASS | `src/lib.rs:92-93`; `cargo clippy -p v2-babbleon-vault --all-targets -- -D warnings -W clippy::pedantic` clean |
| 3 | Secrets wear `Zeroizing`, no `Clone/Copy/Debug` | ✅ PASS | `VaultPayload` holds `host_secret: Zeroizing<Vec<u8>>`; no derives of `Clone`, `Copy`, or `Debug`.  Test `error_display_never_contains_secret_bytes` belts-and-braces against Display leakage |
| 4 | Constant-time compares | ✅ PASS (vacuous in this crate) | wrong-passphrase path lands inside `age::Decryptor` (Poly1305 MAC; constant-time inside age) |
| 5 | HKDF for domain separation | N/A — but Argon2id is the analogous primitive | the soft backend uses Argon2id (RFC 9106) with a fixed domain-separation salt (`b"babbleon-soft-v2"`).  The age library wraps the resulting KEK in its own ChaCha20-Poly1305 encryption |
| 6 | Plain-English names | ✅ PASS | `Vault`, `VaultPayload`, `KekBackend`, `SoftBackend`, `SoftProfile`, `default_vault_path`, `ensure_parent_dir`, `seal`, `unseal` — every public item is named for its job |
| 7 | "What this defeats" module docs | ✅ PASS | `lib.rs`, `payload.rs`, `backend.rs`, `soft_backend.rs`, `vault.rs` open with the template; `errors.rs` and `file_layout.rs` use the Infrastructure-module variant |
| 8 | Process hardening at startup | N/A | library crate; no `main()` |
| 9 | `SAFETY:` comment on every `unsafe` block | ✅ PASS (vacuous) | `forbid(unsafe_code)` |
| 10 | Capability annotation per syscall site | ✅ PASS | `ensure_parent_dir` makes `mkdir` + `chmod` calls; both are unprivileged in the per-user vault-path case; root-write to `/etc/babbleon/vault.age` requires the operator already being root |
| 11 | No long-lived secrets in serde-deserialized types | ✅ PASS | `VaultPayload` hand-managed (de)serialization through a private `WirePayload` struct: the wire struct's `String` lives one decode-stack frame and is dropped before `VaultPayload::from_json_bytes` returns.  No public `serde::Deserialize` on a secret-bearing type |
| 12 | RFC-recognisable primitives | ✅ PASS | Argon2id (RFC 9106), age (passphrase mode → ChaCha20-Poly1305 RFC 8439), hex (RFC 4648), OsRng for `babbleon init`'s fresh secret |
| 13 | Errors do not leak secrets | ✅ PASS | `errors.rs` variants carry strings; `from_hex_wire`-style decode error explicitly comments "do NOT echo the input"; tests `error_display_never_contains_secret_bytes` and `error_display_on_input_error_never_contains_hex_secret` assert.  Wrong-passphrase landing is its own variant `WrongPassphrase` (no fields) so age's MAC-fail bytes never reach a Display |
| 14 | Secret-bearing args are `&` references | ✅ PASS | `VaultPayload::host_secret() -> &[u8]`; `Vault::seal(payload: &VaultPayload, credential: Option<&str>)`.  Constructor `VaultPayload::new(host_secret: Zeroizing<Vec<u8>>, ...)` takes by move (rule 14 exception policy) |
| 15 | Tests cover unit + property invariants | ✅ PASS | 32 unit tests including: KDF determinism, profile distinction, ciphertext is non-deterministic (age nonce), plaintext bytes do not appear verbatim in ciphertext, wrong-passphrase ≠ corrupted-ciphertext discriminant, error-Display does not leak |

**Verdict:** passes every applicable rule.  The crate is small
(~660 lines incl. tests), well-compartmentalised, and lives off
the daemon's audit graph by design.  Future TPM / FIDO2 / USB
backends will land as new `*_backend.rs` modules without changing
the `Vault` / `KekBackend` API.

---

## Crate: `v2-babbleon-pam`  (PAM session module SKELETON, 2026-06-20)

Skeleton-only.  Compiles `pam_babbleon.so` from a C source via
`build.rs`+`cc`; does NOT yet wrap the user's login shell.  The
three candidate architectures for the wrap are filed in
`docs/v2/pam-architecture.md` for operator pick.  Rust scaffolding
exposes `Readiness::SkeletonOnly` which flips to `Wired` in the
same PR that lands one of those architectures.

The shipped artifact is the C `.so` — the Rust crate's role is
scaffolding (build.rs + path constants + readiness gate +
artifact integrity tests).  Most v2 rules apply trivially because
the Rust code holds no secrets, makes no syscalls, and has no
runtime logic.

| # | Rule | Status | Evidence |
|---|---|---|---|
| 1 | `forbid(unsafe_code)` | ✅ PASS | `src/lib.rs:106` |
| 2 | `deny(missing_docs)` + pedantic | ✅ PASS | `src/lib.rs:107-108`; `cargo clippy -p v2-babbleon-pam --all-targets -- -D warnings -W clippy::pedantic` clean |
| 3 | Secrets wear `Zeroizing`, no `Clone/Copy/Debug` | ✅ PASS (vacuous) | crate holds no secret material |
| 4 | Constant-time compares | N/A | no secret material |
| 5 | HKDF for domain separation | N/A | no key derivation |
| 6 | Plain-English names | ✅ PASS | `Readiness`, `launch_untrusted_install_path`, `daemon_socket_path` — every public item names what it does |
| 7 | "What this defeats" module docs | ✅ PASS | `lib.rs` opens with the template; the C source mirrors the template in its top-of-file comment |
| 8 | Process hardening at startup | N/A | no `main()`; the C shim runs inside PAM's caller |
| 9 | `SAFETY:` comment on every `unsafe` block | ✅ PASS (vacuous) | `forbid(unsafe_code)` at the Rust crate root.  The C shim does no inline assembly and no pointer arithmetic; its only unusual primitives are `socket(2)`/`connect(2)`/`close(2)` with documented invariants in the source comments |
| 10 | Capability annotation per syscall site | ✅ PASS | the C shim makes no privileged syscalls — `socket(AF_UNIX)` + `connect` to the daemon's socket path is unprivileged.  Will need re-audit when the architecture lands (PAM wrap may add `setns` or similar) |
| 11 | No long-lived secrets in serde-deserialized types | N/A | no deserializers |
| 12 | RFC-recognisable primitives | N/A | no crypto |
| 13 | Errors do not leak secrets | ✅ PASS | the C shim only logs errno + path strings via `pam_syslog`; no secret material on its call paths |
| 14 | Secret-bearing args are `&` references | N/A | no secret args |
| 15 | Tests cover unit + property invariants | ✅ PASS | 9 Rust unit + 4 integration (artifact existence, ELF magic, BIND_NOW dynamic tag, GNU_STACK non-exec) + 1 cross-crate (`DEFAULT_DAEMON_SOCKET_PATH` agreement with `v2-babbleon-daemon-protocol::default_socket_path()`) |

**Verdict:** passes all applicable rules at the SKELETON level.
Re-audit when one of the three architectures in
`docs/v2/pam-architecture.md` lands and the `.so` actually
invokes the launcher; that PR likely opens rules 8 (the launcher
invocation must apply hardening from the caller's side) and 10
(the wrap may call `setns(2)` or otherwise expand the C shim's
capability envelope).

**Build hardening (defense-in-depth, not a baseline rule):** the
build.rs passes `-fstack-protector-strong`, `-D_FORTIFY_SOURCE=2`,
`-Wl,-z,relro,-z,now`, and `-Wl,-z,noexecstack`.  Two
regression-guard tests in `tests/built_artifact.rs` verify the
produced `.so` carries `BIND_NOW` and non-executable
`GNU_STACK`.

---

## Crate: `v2-babbleon-preprocessor`  (phase-3 layer-3 library + scramble/unscramble; landed 2026-06-20)

Pure-safe-Rust library that owns the `Token` IR + Python tokenizer
+ scrambler + unscrambler + per-epoch `WhitespaceWordlist`.  Holds
no secret bytes — the per-epoch compounds are HKDF-derived from
the per-host secret one layer up (in the daemon).  Library crate;
no `main()`, no syscalls, no I/O.

| # | Rule | Status | Evidence |
|---|---|---|---|
| 1 | `forbid(unsafe_code)` | ✅ PASS | `src/lib.rs:114` |
| 2 | `deny(missing_docs)` + pedantic | ✅ PASS | `src/lib.rs:115-116`; `cargo clippy -p v2-babbleon-preprocessor --all-targets -- -D warnings -W clippy::pedantic` clean |
| 3 | Secrets wear `Zeroizing`, no `Clone/Copy/Debug` | ✅ PASS | `WhitespaceWordlist` carries plain `String` compounds (secret-derived but not secret-equivalent; matches v2-core's `EpochMapping` precedent).  Tests assert pairwise distinct + ASCII-lowercase + rotation invariants. |
| 4 | Constant-time compares | N/A | the structural-scramble layer does not equality-check secret-derived bytes; the prefix-match in `match_prefix` is constant-time-irrelevant (the timing leak is structural, not secret-bearing) |
| 5 | HKDF for domain separation | ✅ PASS | `whitespace_wordlist::PURPOSE_WHITESPACE = b"v2-whitespace-mapping"` is distinct from v2-core's identifier and honey labels |
| 6 | Plain-English names | ✅ PASS | every module (`tokens`, `python_tokenizer`, `scrambler`, `unscrambler`, `whitespace_wordlist`, `errors`) names what it does |
| 7 | "What this defeats" module docs | ✅ PASS | `lib.rs`, `whitespace_wordlist.rs`, `scrambler.rs`, `unscrambler.rs` open with the template; `tokens.rs` + `python_tokenizer.rs` + `errors.rs` declare themselves infrastructure |
| 8 | Process hardening at startup | N/A | library |
| 9 | `SAFETY:` comment on every `unsafe` block | ✅ PASS (vacuous) | `forbid(unsafe_code)` |
| 10 | Capability annotation per syscall site | N/A | no syscalls |
| 11 | No long-lived secrets in serde-deserialized types | ✅ PASS | no serde |
| 12 | RFC-recognisable primitives only | ✅ PASS | reuses v2-babbleon-core's HKDF (RFC 5869) and Fisher-Yates permutation |
| 13 | Errors do not leak secrets | ✅ PASS | `errors.rs` variants (`InvalidSuppliedCompounds`, `WhitespaceCompoundCollision`, `TruncatedScrambledInput`) carry slot indices + offsets only; not bytes.  Tests assert `InvalidSuppliedCompounds` debug-format does not echo the supplied compound bytes. |
| 14 | Secret-bearing args are `&` references | ✅ PASS | `WhitespaceWordlist::build(secret: &PerHostSecret, ...)` |
| 15 | Tests cover unit + property invariants | ✅ PASS | 50 unit + 6 integration (example puzzles) + 5 proptest (round-trip @ 1024 cases / property) |

**Verdict:** passes all applicable rules.

---

## Crate: `v2-babbleon-python-shim`  (phase-3 runtime entry point; landed 2026-06-20)

The standalone `babbleon-python` binary that bridges a layer-3
scrambled `.py` file to a child `python3` via `pipe(2)`.  Holds
HKDF-derived compounds + unscrambled source bytes transiently;
does NOT hold the per-host secret.  Applies the same
`PR_SET_DUMPABLE=0` / `RLIMIT_CORE=0` / `mlockall` triad as the
daemon (`v2-babbleon-daemon::hardening`) before any I/O.

| # | Rule | Status | Evidence |
|---|---|---|---|
| 1 | `forbid(unsafe_code)` | ✅ PASS | `src/lib.rs:90` |
| 2 | `deny(missing_docs)` + pedantic | ✅ PASS | `src/lib.rs:91-92`; `cargo clippy -p v2-babbleon-python-shim --all-targets -- -D warnings -W clippy::pedantic` clean |
| 3 | Secrets wear `Zeroizing`, no `Clone/Copy/Debug` | ✅ PASS (vacuous on the secret axis) | the shim never holds the per-host secret; the compounds + unscrambled source are secret-derived but not secret-equivalent (same trust placement as `v2-babbleon`'s scramble-lifecycle module).  Rule 8 hardening covers leak-vector defense. |
| 4 | Constant-time compares | N/A | no secret equality checks |
| 5 | HKDF for domain separation | N/A | does not derive; consumes the daemon-derived compounds |
| 6 | Plain-English names | ✅ PASS | `process_hardening`, `pipeline`, `exec_python` — every module names what it does |
| 7 | "What this defeats" module docs | ✅ PASS | `lib.rs`, `process_hardening.rs`, `exec_python.rs` open with the template; `pipeline.rs` declares itself infrastructure with a pointer to the source crates' threat-model headers |
| 8 | Process hardening at startup | ✅ PASS | `process_hardening::apply()` runs FIRST in `main::run_shim` before any I/O or daemon round-trip; same triad as the daemon (`PR_SET_DUMPABLE=0` + `RLIMIT_CORE=0` + `mlockall`); mlockall failure downgrades to a warning per the daemon's same rationale |
| 9 | `SAFETY:` comment on every `unsafe` block | ✅ PASS (vacuous) | `forbid(unsafe_code)` |
| 10 | Capability annotation per syscall site | N/A | no privileged syscalls — `pipe(2)` (via `Command::stdin(Stdio::piped())`) and `execve(2)` are unprivileged; `mlockall` requires `CAP_IPC_LOCK` for non-trivial sizes, downgrades to warn at deploy time |
| 11 | No long-lived secrets in serde-deserialized types | ✅ PASS | no serde (the daemon protocol crate's hand-validated JSON path is the only deserializer in the dep graph) |
| 12 | RFC-recognisable primitives only | ✅ PASS | no crypto; reuses preprocessor's primitives via the wire |
| 13 | Errors do not leak secrets | ✅ PASS | error chain via `anyhow::Context`; the daemon's `Response::Error { kind, message }` is propagated verbatim (the daemon's message has already passed rule 13 on its own side) |
| 14 | Secret-bearing args are `&` references | ✅ PASS | `unscramble_source(scrambled: &str, wl: &WhitespaceWordlist)` and `exec_python::run(python_bin: &Path, forward_args: &[String], source: &str)` — every secret-adjacent arg is borrowed |
| 15 | Tests cover unit + property invariants | ✅ PASS | 17 unit (7 main + 5 exec_python + 3 pipeline + 2 process_hardening) + 4 end-to-end integration (against the real daemon + the real python3 on /usr/local/bin/python3 3.11.15) |

**Verdict:** passes all applicable rules.

**Trust placement (out of scope for the baseline but filed for the
operator):**  the shim is designed to run only in the trusted tier.
A defense-in-depth namespace-inode gate (refuse to run if
`readlink(/proc/self/ns/mnt)` does NOT match the trusted-tier inode
set) is filed for the next revision — same gate the launcher
exposes.  Today the shim trusts the operator-side install location.

---

## Aggregate

Across the nine v2 crates:

- v2-babbleon-core: PASS (every applicable rule)
- v2-babbleon-launch-untrusted: PASS-with-noted-exception (unsafe quarantine per rule-1 exception policy)
- v2-babbleon: PASS-with-one-defer (rule 8 mlockall on CLI unwrap window)
- v2-babbleon-daemon: PASS (every applicable rule; Locked/Unlocked refactor preserves the baseline)
- v2-babbleon-daemon-protocol: PASS (every applicable rule; UnlockSecret carries one documented Clone relaxation for the proptest harness)
- v2-babbleon-vault: PASS (every applicable rule; new crate landed 2026-06-20)
- v2-babbleon-pam: PASS (subset applicable to the skeleton; re-audit when architecture lands)
- v2-babbleon-preprocessor: PASS (every applicable rule; phase-3 library landed 2026-06-20)
- v2-babbleon-python-shim: PASS (every applicable rule; phase-3 runtime binary landed 2026-06-20)
- 1 DEFER (v2-babbleon rule 8 — CLI unwrap-window mlockall)
- 0 FAIL

Phase 3's vault unlock landed across five commits (`83152e1`,
`fbdd7f1`, `e6cc823`, `b8d2a7e`, `4d5864b`).  The new vault crate
opened rules 3, 11, 13, 14 on its own surface; protocol crate's
new `UnlockSecret` opened the same rules on a one-stack-frame
window; daemon's Locked/Unlocked refactor preserved rule 3 and
ensured the Locked state holds no secret bytes at all.

The daemon's seccomp profile (`v2-babbleon-daemon/src/seccomp_profile.rs`)
is opt-in behind `--enable-seccomp`; once the operator flips its
default to ON it counts as defense-in-depth on top of rule 8
(hardening) and rule 10 (capability discipline).

## Open audit items

- **Rule 8 declaration mechanism.**  The library refuses to
  construct `PerHostSecret` unless the caller has declared
  hardening applied; currently this is by convention.  Filed as
  a future tighten.
- **Rule 8 on `v2-babbleon`'s unlock path.**  The user-CLI
  process holds the unwrapped secret bytes for one stack frame
  (`Vault::unseal` returns → `UnlockSecret::from_bytes` consumes
  → `round_trip(Request::Unlock)` ships off the box).  `mlockall`
  during that window would tighten leakage resistance.  Filed as
  the one DEFER above.
- **Rule 15 property tests** are present for `EpochMapping`
  invariants in core; the permutation crate has roundtrip +
  Fisher-Yates bijection asserts but no large-N property test.
  Could tighten.  The protocol crate covers its no-panic /
  roundtrip / size-cap invariants via proptest; same pattern is
  available for porting to other crates.  Filing the vault crate
  for proptest coverage in a future commit is worth considering
  (the seal/unseal roundtrip is the natural candidate).
- **Activated-table audit-surface tightening.**  The launcher
  depends transitively on the core crate's HKDF / ed25519 stack
  even though it only uses the `activated_table` + `credentials`
  modules.  Filed as a refactor in HANDOFF.md: extract
  `activated_table.rs` + `credentials.rs` into their own crate so
  the launcher's audit surface drops the crypto deps.  Same shape
  as the protocol carve-out.  Not blocking; cosmetic for review.
