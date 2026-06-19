# Security-baseline self-audit — v2 crates as of 2026-06-19

Cross-reference: `docs/v2/security-baseline.md` (the 15 rules).

This document records the audit findings for every v2 crate as of
the snapshot below.  Each rule is checked per crate.  A "PASS"
entry cites the specific file / line evidence; a "DEFER" entry
names the follow-up commit that must land before the crate is
considered shippable.

Snapshot HEAD: `75abdca` (post protocol carve-out + proptest suite,
2026-06-19 night).  Previous snapshot `e42f81c` had v2-babbleon-daemon
as a CLI-only skeleton with no socket loop, no state, no
materialisation; that state changed across `b326107` (protocol),
`ac37d0f` (state), `9dd8e86` (handlers), `60617cb` (socket),
`1a81b77` (main wired end-to-end), `ca2268e` (hardening),
`5b6f58e` (materialisation), and `9574c23` (protocol carve-out).
The daemon's row below is refreshed accordingly, and a new row
for `v2-babbleon-daemon-protocol` is added.

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

## Crate: `v2-babbleon`  (user-facing CLI)

| # | Rule | Status | Evidence |
|---|---|---|---|
| 1 | `forbid(unsafe_code)` | ✅ PASS | `src/main.rs:30` |
| 2 | `deny(missing_docs)` + pedantic | ✅ PASS | `src/main.rs:31`; clippy clean |
| 3-5, 8 | secret-related rules | N/A | this crate is a thin client; secrets live in the daemon |
| 6 | plain-English names | ✅ PASS | subcommand names per docs/v2/naming-conventions.md |
| 7 | module docs | ✅ PASS | `main.rs` opens with the "What this defeats" template |
| 11 | no long-lived secrets in serde | ✅ PASS (vacuous) | no serde-deserialized types yet |
| 13 | errors do not leak secrets | ✅ PASS | uses anyhow with non-secret strings |
| 15 | tests | ✅ PASS | 3 CLI parse-roundtrip tests |

**Verdict:** passes (subset applicable).  Note: phase-2 stubs every
subcommand; the actual implementations will need re-audit once the
daemon socket protocol is wired up.

---

## Crate: `v2-babbleon-daemon`  (shipping, phase-2 stub-secret mode)

| # | Rule | Status | Evidence |
|---|---|---|---|
| 1 | `forbid(unsafe_code)` | ✅ PASS | `src/lib.rs:63`, `src/main.rs:10` |
| 2 | `deny(missing_docs)` + pedantic | ✅ PASS | `src/lib.rs:64-65`; `cargo clippy -p v2-babbleon-daemon --all-targets -- -D warnings` clean |
| 3 | Secrets wear `Zeroizing`, no `Clone/Copy/Debug` | ✅ PASS | `state.rs:83` `DaemonState` holds `PerHostSecret` by move (no derives); explicit comment at `state.rs:299-300` notes Clone/Copy/Debug are deliberately not derived to preserve `PerHostSecret`'s zeroize-on-drop |
| 4 | Constant-time compares | ✅ PASS (vacuous in this crate) | no secret-to-secret compare in the daemon; the core crate's `crypto_compare` is reached transitively via `MappingBuilder::is_honey` calls |
| 5 | HKDF for domain separation | ✅ PASS (delegated) | daemon does not derive keys directly; it calls `MappingBuilder::new(secret, wordlist).build(...)` which performs HKDF inside the core crate |
| 6 | Plain-English names | ✅ PASS | `state`, `handlers`, `socket`, `hardening`, `materialization`, `cli` — every module is named for its job |
| 7 | "What this defeats" module docs | ✅ PASS | `lib.rs`, `state.rs`, `socket.rs`, `hardening.rs`, `materialization.rs` open with the template; `handlers.rs`, `errors.rs`, `cli.rs` use the Infrastructure-module variant |
| 8 | Process hardening at startup | ✅ PASS | `hardening::apply_secret_hygiene` invoked from `main.rs` before `PerHostSecret::from_bytes`: `PR_SET_DUMPABLE=0` + `RLIMIT_CORE=0` (fatal on failure) and `mlockall` (best-effort) |
| 9 | `SAFETY:` comment on every `unsafe` block | ✅ PASS (vacuous) | `forbid(unsafe_code)` at crate root |
| 10 | Capability annotation per syscall site | ✅ PASS | hardening + materialise sites carry capability comments; socket bind is unprivileged (`UnixListener::bind`); the daemon runs as a dedicated UID with no caps per `docs/v2/least-privilege.md` |
| 11 | No long-lived secrets in serde-deserialized types | ✅ PASS | the daemon's only deserializer surface is the wire protocol, which lives in `v2-babbleon-daemon-protocol` and is hand-parsed via `serde_json::Value` (no `#[derive(Deserialize)]` on operator-influenceable types) |
| 12 | RFC-recognisable primitives | ✅ PASS (delegated) | daemon uses core's HKDF-SHA-256 / Fisher-Yates / Ed25519 wrappers; introduces no new crypto |
| 13 | Errors do not leak secrets | ✅ PASS | `errors.rs` variants carry strings; reviewed: no construction site passes secret bytes; `handlers::error_response` maps daemon `Error` to wire `Response::Error` with `Display` form only |
| 14 | Secret-bearing args are `&` references | ✅ PASS | the secret enters by move via `DaemonState::new(secret: PerHostSecret, ...)` and stays in the struct for the daemon's lifetime; `MappingBuilder::new(&self.secret, ...)` accesses it by reference thereafter |
| 15 | Tests cover unit + property invariants | ✅ PASS | 63 unit + 3 client_round_trip integration + 5 end_to_end_binary integration; `state.rs` rotation tests assert epoch advance + scrambled-name change as invariants over the secret/wordlist domain |

**Verdict:** the daemon passes every applicable rule at phase-2
ship.  Phase 3 (real vault unlock) will introduce a new
`Request::Unlock { vault_payload }` surface — re-audit rule 11
once that variant lands (the variant must use the same hand-parsed
discipline already established for the other request kinds).

---

## Crate: `v2-babbleon-daemon-protocol`  (new — protocol carve-out)

The wire protocol + client + canonical socket path, carved out of
the daemon crate so its peers (launcher, user CLI) link only the
small protocol surface.  No state, no secret, no I/O loop, no
materialisation; no `v2-babbleon-core` dependency.

| # | Rule | Status | Evidence |
|---|---|---|---|
| 1 | `forbid(unsafe_code)` | ✅ PASS | `src/lib.rs:38` |
| 2 | `deny(missing_docs)` + pedantic | ✅ PASS | `src/lib.rs:39-40`; `cargo clippy -p v2-babbleon-daemon-protocol --all-targets -- -D warnings` clean |
| 3 | Secrets wear `Zeroizing`, no `Clone/Copy/Debug` | ✅ PASS (vacuous) | crate holds NO secret material — that's the point of the carve-out |
| 4 | Constant-time compares | N/A | no secret material |
| 5 | HKDF for domain separation | N/A | no key derivation |
| 6 | Plain-English names | ✅ PASS | `protocol`, `client`, `socket_path`, `errors` — every module describes its job |
| 7 | "What this defeats" module docs | ✅ PASS | `lib.rs` and `protocol.rs` open with the template; `client.rs`, `socket_path.rs`, `errors.rs` use the Infrastructure-module variant |
| 8 | Process hardening at startup | N/A | library crate; no `main()` |
| 9 | `SAFETY:` comment on every `unsafe` block | ✅ PASS (vacuous) | `forbid(unsafe_code)` |
| 10 | Capability annotation per syscall site | ✅ PASS (vacuous) | crate makes no privileged syscalls — `UnixStream::connect` runs as the caller's UID with no extra caps |
| 11 | No long-lived secrets in serde-deserialized types | ✅ PASS | hand-parsed `serde_json::Value` throughout `protocol.rs`; no `#[derive(Deserialize)]` on `Request` / `Response` / `ErrorKind` |
| 12 | RFC-recognisable primitives | N/A | no crypto |
| 13 | Errors do not leak secrets | ✅ PASS | `errors.rs` carries two variants (`Ipc`, `ActivatedTable`); both wrap `String` built from non-secret sources |
| 14 | Secret-bearing args are `&` references | N/A | no secret args |
| 15 | Tests cover unit + property invariants | ✅ PASS | 27 unit (22 protocol roundtrip + 1 client connection-error + 2 socket_path + 2 minor) + 6 proptest properties × 1024 cases each = 6144 random inputs covering no-panic / roundtrip / oversize-reject / byte-preservation invariants |

**Verdict:** passes all applicable rules.  The crate exists
specifically to be the *narrow* surface that audit reviewers
study; that narrowness is the security-baseline expression of
the carve-out's purpose.

---

## Aggregate

Across the five v2 crates:

- 2 PASS, 2 PASS-with-noted-exception, 1 PASS-vacuous: every rule
  passes in the crate where it applies; the protocol-crate row
  passes 8 rules outright and is N/A on the 7 that don't apply
  to a library with no secrets / no syscalls / no crypto.
- 0 DEFER (every rule applicable to the daemon now lands; the
  previous 8 DEFERs against the daemon-as-skeleton closed across
  `b326107` / `ac37d0f` / `9dd8e86` / `60617cb` / `1a81b77` /
  `ca2268e` / `5b6f58e` / `9574c23`).
- 0 FAIL.

Phase 3 will introduce vault unlock and re-open three rules for
re-audit (3, 11, 14) on the new code path.

## Open audit items

- **Rule 8 declaration mechanism.**  The library refuses to
  construct `PerHostSecret` unless the caller has declared
  hardening applied; currently this is by convention.  Filed as
  a future tighten.
- **Rule 15 property tests** are present for `EpochMapping`
  invariants in core; the permutation crate has roundtrip +
  Fisher-Yates bijection asserts but no large-N property test.
  Could tighten.  As of this snapshot, the protocol crate has
  added proptests covering its own no-panic / roundtrip / size-cap
  invariants — pattern is available for porting to other crates.
- **Activated-table audit-surface tightening.**  The launcher
  depends transitively on the core crate's HKDF / ed25519 stack
  even though it only uses the `activated_table` + `credentials`
  modules.  Filed as a refactor in HANDOFF.md: extract
  `activated_table.rs` + `credentials.rs` into their own crate so
  the launcher's audit surface drops the crypto deps.  Same shape
  as the protocol carve-out that closed item 3.  Not blocking;
  cosmetic for review.
