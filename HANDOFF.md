# Babbleon — Session Handoff

Branch (push target): `claude/magical-turing-mele8c`
Date: 2026-06-15
Last commit before this session: `a8351bd` — process_hardening: PR_SET_DUMPABLE + RLIMIT_CORE + mlockall

---

## Where the project sits

M3 (Linux namespace enforcement) and M3.5 (deception layer) are
shipped. The two M3.5+ items that were filed against the original
"connected attacker" / Threat-B framing are in. The full overnight
security-practice cluster has now landed in this branch.

Total tests: **123 across the workspace, all green.** (was 81 at
the start of this session's predecessor.)

The session before this one had restructured the threat model into
**two underlying threats** (A disconnected / B connected) with **four
expressions** (E1 solo internal, E2 solo external, E3 hybrid, E4
adversarial network of LLMs). See `docs/threat-model.md`.

---

## What this overnight session shipped

The 12-item priority cluster called out by the prior handoff was
worked top-to-bottom, plus follow-ups and CWE Top 25 audit items.

Code-bearing commits in this session, in order:

1. `kdf: migrate to HKDF-SHA-256 (RFC 5869)` — new
   `crates/babbleon/src/mapping/kdf.rs`; `Mapper::purpose_seed` and
   `fpe::derive_chacha_seed` both call through it.
2. `fmt: cargo fmt sweep of latent drift` — restored
   `cargo fmt --check` to green across the workspace.
3. `crypto: constant-time comparison helper + is_honey adoption` —
   new `crates/babbleon/src/crypto.rs::ct_eq`; `MappingTable::is_honey`
   uses it with no short-circuit.
4. `audit: Ed25519-sign each entry` —
   `ChainedAuditLog::open_signed` / `verify_signed`; new
   `SigningPayload` so signing bytes match the verifier's
   reconstruction.
5. `events: length-bound the honey-FIFO line reader (CWE-400)` —
   `read_bounded_line` + `discard_to_newline`,
   `MAX_HONEY_LINE_BYTES = 16 KiB`.
6. `tests: proptest properties for the mapping layer` — 6 properties
   at 16 cases each (~56 s suite).
7. `vault: per-vault unlock rate-limit with exponential backoff` —
   new `crates/babbleon/src/vault/attempts.rs`; `AttemptTracker`
   sidecar (`<vault>.attempts`); wired into `Session::unlock`.
8. `policies: AppArmor + SELinux confinement templates` — new
   `policies/{apparmor,selinux}/` with install README.
9. `ci: SBOM job, dependabot, workflow permissions, CODEOWNERS,
   deny sweep` — `.github/workflows/ci.yml` SBOM job, new
   `.github/dependabot.yml`, `CODEOWNERS`, tightened `deny.toml`.
10. `release: sigstore signing + SLSA L3 provenance + scorecard CI` —
    `.github/workflows/release.yml`, `scorecard.yml`,
    `docs/verify-release.md`.
11. `docs: CWE Top 25 (2024) documentary audit` —
    `docs/cwe-top25-audit.md` (one new finding: CWE-770).
12. `fpe: bound the permutation cache at CACHE_MAX_ENTRIES (CWE-770)` —
    closes the cache-eviction finding.
13. `docs+ci: secure-development-policy + cargo-llvm-cov coverage job` —
    `docs/secure-development-policy.md` + `coverage` CI job.
14. `fuzz+miri: cargo-fuzz scaffolding + miri CI job` — `fuzz/`
    crate with three targets, new `miri` CI job.
15. `ci: CodeQL SAST` — `.github/workflows/codeql.yml`.

---

## The original 12-item priority list (status)

1. `SECURITY.md` / RFC 9116 ✅ pre-session
2. Memory zeroization (`zeroize`) ✅ pre-session
3. Constant-time comparison (`subtle`) ✅ this session
4. Daemon hardening (`PR_SET_DUMPABLE`, `RLIMIT_CORE`, `mlockall`) ✅ pre-session
5. `SAFETY:` comments ✅ pre-session
6. HKDF (RFC 5869) ✅ this session
7. Vault unlock rate-limiting ✅ this session
8. Property tests + fuzz harness scaffolding ✅ this session (both)
9. SBOM generation in CI ✅ this session
10. Sigstore / cosign release-signing ✅ this session (with SLSA L3)
11. AppArmor / SELinux profile templates ✅ this session (both)
12. Ed25519 audit-log signing ✅ this session

All 12 closed.

---

## What's NOT being done this session

- Anything that needs hardware (FIDO2, TPM, bare-metal NS validation).
- The `tools/scrambler/example-puzzles/` deliverable (needs human
  curation).
- The structure-scrambling research line — needs research write-up
  first.
- Branch protection on `main` — this is a remote-side GitHub setting,
  not code; documented in `docs/secure-development-policy.md`.

---

## Open follow-ups (the next session's pickup queue)

Drawn from the unchecked items in TODO.md after this session:

**Background work for M3.5+++:**
- Background wordlist-permutation pre-build (needed for the rotation
  rate that defeats Threat B).
- Unified runtime-table wrapper (collapses rotation to one atomic
  table write).

**Manifest scale:**
- OverlayFS per-app writable upper layers.
- O(N) bind cost at large manifest size.

**M5 enterprise (private crate):**
- Escrow backend, SIEM event sinks, console.

**Hardware-blocked:**
- FIDO2 wire-up, TPM2 PCR-sealed backend, TPM authorized policy,
  tpm2-abrmd matrix.

**CI follow-ups:**
- Weekly cargo-fuzz smoke runs on a scheduled workflow.
- Reproducible-build verification CI job (musl-static claim).
- `cargo-vet` for transitive-dep audits.

**Process items (need operator action, not code):**
- Branch protection on `main`.
- OpenSSF Best Practices badge.
- Move CodeQL `language` matrix to include rust + cpp when upstream
  support stabilises.

**Standards:**
- STRIDE-formatted threat model (have a threat model; needs the
  STRIDE table-of-tables shape for procurement reviewers).

**Research:**
- Operator scrambling, whitespace-as-words, code-order scrambling,
  junk-line decoys, multi-language wordlists (v2/v3).

---

## Key file map (refreshed)

```
crates/babbleon/src/
  audit.rs            — ChainedAuditLog::open_signed + verify_signed
  crypto.rs           — ct_eq() constant-time helper (NEW)
  enforcement/
    linux_ns.rs       — mount-namespace driver
    wrapper.rs        — unified shell template with honey + stale branches
    seccomp.rs        — block_process_inspection_syscalls()
    landlock.rs       — Landlock LSM sandbox
    response.rs       — ResponsePolicy + HoneyResponder
    ebpf.rs           — eBPF-LSM scaffold; kernel-gated at 6.1
    syscalls.rs       — ALL nix/libc kernel calls
  events.rs           — HoneyFifoReader with bounded read (CWE-400)
  mapping/
    kdf.rs            — HKDF-SHA-256 subkey derivation (NEW)
    mapper.rs         — uses kdf::derive_subkey_32; is_honey -> ct_eq
    fpe.rs            — uses kdf; Cache with FIFO eviction (CWE-770)
  vault/
    attempts.rs       — AttemptTracker, sidecar file, backoff (NEW)
    soft.rs           — Argon2id KEK
    usb.rs            — keyfile + optional passphrase
    fido2.rs          — skeleton; blocked on hardware
    tpm.rs            — skeleton; blocked on hardware
  process_hardening.rs — PR_SET_DUMPABLE / RLIMIT_CORE / mlockall
  session.rs          — unlock now rate-limit-gated

crates/babbleon/tests/
  corpus_fingerprint.rs
  enforcement.rs
  fingerprint.rs
  mapping_properties.rs — 6 proptest properties (NEW)

docs/
  threat-model.md
  standards-survey.md
  operator.md
  cwe-top25-audit.md            (NEW)
  secure-development-policy.md  (NEW)
  verify-release.md             (NEW)

policies/                       (NEW directory)
  apparmor/usr.local.bin.babbleon
  selinux/{babbleon.te,.fc,.if}
  README.md

fuzz/                           (NEW directory)
  Cargo.toml
  README.md
  fuzz_targets/{honey_fifo_line,fpe_roundtrip,wrapper_render}.rs

.github/
  dependabot.yml                (NEW)
  workflows/
    ci.yml                      (perms blocks + SBOM + coverage + miri)
    scorecard.yml               (NEW)
    release.yml                 (NEW)
    codeql.yml                  (NEW)

CODEOWNERS                      (NEW)
deny.toml                       (tightened: unknown-git deny, RUSTSEC ignore)
```

---

## Git / branch hygiene

Push target this session: `claude/magical-turing-mele8c` only.

The repo stop-hook insists on `noreply@anthropic.com` as committer.
This session used `-c user.name=Claude -c user.email=noreply@anthropic.com`
per commit to satisfy that.

After each commit:
`git push origin HEAD:claude/magical-turing-mele8c`

---

## Live test status

122 tests across the workspace (was 81), all green.

- 101 lib unit tests (was 69)
- 3 corpus-fingerprint tests
- 5 enforcement tests
- 4 fingerprint tests
- 6 mapping property tests (NEW)
- 3 CLI unit tests

Coverage CI job (cargo-llvm-cov) added; numbers tracked in the
`coverage` artifact per run.

Bare-metal validation still deferred until hardware arrives.
