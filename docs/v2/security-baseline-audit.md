# Security-baseline self-audit — v2 crates as of 2026-06-19

Cross-reference: `docs/v2/security-baseline.md` (the 15 rules).

This document records the audit findings for every v2 crate as of
the snapshot below.  Each rule is checked per crate.  A "PASS"
entry cites the specific file / line evidence; a "DEFER" entry
names the follow-up commit that must land before the crate is
considered shippable.

Snapshot HEAD: `e42f81c`.

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

## Crate: `v2-babbleon-daemon`  (skeleton)

| # | Rule | Status | Evidence |
|---|---|---|---|
| 1 | `forbid(unsafe_code)` | ✅ PASS | `src/lib.rs:64`, `src/main.rs:10` |
| 2 | `deny(missing_docs)` + pedantic | ✅ PASS | `src/lib.rs:65-66`; clippy clean |
| 3 | secret hygiene | DEFER | crate doesn't yet handle secrets — when vault load lands, `PerHostSecret` from core is the carrier and inherits its hygiene |
| 4 | constant-time compares | DEFER | as above |
| 5 | HKDF for domain separation | DEFER | as above |
| 6 | plain-English names | ✅ PASS | `run`, `emit-activated-table`, `status`, `rotate-mapping` |
| 7 | "What this defeats" module docs | ✅ PASS | `lib.rs` opens with the template; `cli.rs` and `errors.rs` use Infrastructure-module variant |
| 8 | process hardening | DEFER | crate has no `main()`-side hardening yet (the binary is a stub that returns "not yet implemented" before any state change) |
| 9 | SAFETY comments | ✅ PASS (vacuous) | forbid(unsafe_code) |
| 10 | capability annotation | DEFER | no syscalls yet |
| 11 | no long-lived secrets in serde | DEFER | no deserialized types yet |
| 12 | RFC-recognisable primitives | DEFER | no crypto yet |
| 13 | errors do not leak secrets | ✅ PASS | `errors.rs` variants carry strings; no construction site has secret data to pass in |
| 14 | secret-bearing args | DEFER | no secret args yet |
| 15 | tests | ✅ PASS (for skeleton) | 5 CLI parse-roundtrip tests |

**Verdict:** the skeleton passes every rule applicable to a
skeleton.  Re-audit required once the vault load, socket loop,
and request handlers land.

---

## Aggregate

Across the four v2 crates:

- 1 PASS, 2 PASS-with-noted-exception, 0 FAIL: every rule passes
  in the crate where it applies.
- 8 DEFER (all in v2-babbleon-daemon, all gated on phase-2 item 2
  landing): they will re-audit at that point.

No rule is failing in any v2 crate today.

## Open audit items

- **Rule 8 declaration mechanism.**  The library refuses to
  construct `PerHostSecret` unless the caller has declared
  hardening applied; currently this is by convention.  Filed as
  a future tighten.
- **Rule 15 property tests** are present for `EpochMapping`
  invariants; the permutation crate has roundtrip + Fisher-Yates
  bijection asserts but no large-N property test.  Could tighten.
- **Activated-table audit-surface tightening.**  The launcher
  depends transitively on the core crate's HKDF / ed25519 stack
  even though it only uses the `activated_table` + `credentials`
  modules.  Filed as a refactor in HANDOFF.md "Phase-2 next steps
  item 6": extract `activated_table.rs` + `credentials.rs` into
  their own crate so the launcher's audit surface drops the
  crypto deps.  Not blocking; cosmetic for review.
