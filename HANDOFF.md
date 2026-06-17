# Babbleon — Session Handoff

Branch (push target): `claude/magical-turing-mele8c`
Date: 2026-06-15 (afternoon — v2 transition session, follows the
overnight v1-hardening session below)
Last commit before this session: `aedadda` — docs: update HANDOFF test counts to 132 (lib 111)

---

## Most important update: v2 transition declared

Operator has declared **Babbleon v1 inferior and not for public
release.**  Reasoning:

1. **Identifier-only scramble is shape-defeated.**  Operator tested
   several models; none cracked the scramble blind, all cracked it
   instantly when shown the original.  Structural fingerprinting
   (file-shape recognition) defeats identifier-only scrambling once
   Babbleon is publicly known.
2. **Security conventions were bolted on rather than designed in.**
   The overnight session below closed every item on the security-
   practice priority list and v1 is now correct against the
   surveyed standards — but the integration is patchwork, not
   architectural.
3. **The privilege model is over-broad.**  `babbleon-ns-helper` is
   setuid-root for a setup that needs only four capabilities.

**Phase 0 (now): v2 design docs.**  No source-code changes this
session.  v1 work continues on `magical-turing` because that work
informs v2 even if v1 itself won't ship publicly.

### This session shipped (phase 0)

All doc-only:

- `V2_PLAN.md` (repo root) — v2 vision, why v1 is inferior, crate
  rename table, phase plan (0 docs → 1 core → 2 launcher → 3
  structure-scrambling → 4 multi-lang → 5 hardware → 6 release).
- `docs/v2/structure-scrambling.md` — technical heart of v2.  Five
  composable layers: identifier scramble (v1) + operator scramble
  + whitespace-as-words + code-order reorder + junk decoys.  Plus
  multi-language wordlists.  Runtime preprocessor as the new
  load-bearing component.  Open questions + recommended phase-3
  prototype.
- `docs/v2/naming-conventions.md` — rename discipline locked in
  for v2 day-one.  Binary, crate, module, function, type, test,
  operator-facing names + the v1-name rename table.
- `docs/v2/least-privilege.md` — per-syscall capability audit
  of v1.  `babbleon-ns-helper` found to be 37 capabilities
  over-broad.  v2 install-mode is file capabilities
  (`cap_sys_admin`, `cap_setuid`, `cap_setgid`, `cap_ipc_lock`),
  NOT setuid-root.  Step-by-step lifecycle ordering for NNP +
  caps + seccomp.
- `docs/v2/standards-alignment.md` — v1 standards-survey gaps
  acknowledged honestly.  Most-important miss: **MITRE ATT&CK +
  D3FEND mapping** (essential for any defensive tool).  Other
  misses now filed: NIST 800-190 (container security — direct
  overlap), NIST 800-207 (zero trust), in-toto + TUF, CycloneDX
  vs SPDX (v2 picks **CycloneDX 1.6**), GUAC, CSAF 2.0, SARIF,
  FIPS 140-3 deferral, CIS / DISA STIGs, OWASP SAMM, OWASP
  Top 10.

### Open architectural questions

Decide before phase 1 lands:

1. **Branch vs subtree for v2 source.**  Separate `v2-main`
   branch, or `crates/v2-*` subtree of `main`?
2. **File extension for scrambled source.**  Keep `.py` or
   introduce `.babbleon`?
3. **Preprocessor: standalone binary or library?**  Standalone is
   easier to seccomp-profile; library is faster.  Probably
   standalone for v2.0.
4. **Branch for continuing v1 hardening.**  Stays on
   `magical-turing`?  Or move to `v1-maintenance`?

### What the next session should do

Phase 0 docs to add:

- `docs/v2/threat-model.md` — STRIDE-formatted threat model,
  ATT&CK + D3FEND traceability, NIST 800-190 section mapping,
  NIST 800-207 zero-trust mapping.  Consolidates the references
  from `docs/v2/standards-alignment.md`.
- `docs/v2/security-baseline.md` — the "designed-in from day one"
  checklist every v2 crate must pass before merge.

Or start phase 1 (code):

- Pick branch vs subtree with operator.
- Create `crates/babbleon-core` skeleton.
- Port identifier scramble + tripwires + response policy from v1,
  applying the v2 security baseline and naming conventions.

---

## v1 status (below) — preserved from overnight v1-hardening session

The v1 codebase is at a known-correct-against-standards state.
The phase-0 doc work above does NOT change v1.  Everything below
remains accurate for v1 work.

## Where the project sits

M3 (Linux namespace enforcement) and M3.5 (deception layer) shipped
before this session.  This overnight session worked top-to-bottom
through the 12-item security-practice priority cluster, plus the
follow-ups it surfaced (CWE Top 25 documentary audit, SSDF policy
doc, MAC profile templates, supply-chain hardening).

**Total tests: 132 across the workspace, all green.** (Was 81 at
the start of the predecessor session.)

The threat model from the session before this is unchanged: two
underlying threats (A disconnected / B connected) with four
expressions (E1–E4).  See `docs/threat-model.md`.

---

## What this overnight session shipped (in commit order)

| # | Commit | Subject |
|---|---|---|
| 1 | `72efe9f` | kdf: migrate to HKDF-SHA-256 (RFC 5869) |
| 2 | `8b29498` | fmt: cargo fmt sweep of latent drift |
| 3 | `66a2daa` | crypto: constant-time comparison helper + is_honey adoption |
| 4 | `4847e62` | audit: Ed25519-sign each entry |
| 5 | `7ac15e8` | events: length-bound the honey-FIFO line reader (CWE-400) |
| 6 | `1b93a75` | tests: proptest properties for the mapping layer |
| 7 | `d847283` | vault: per-vault unlock rate-limit with exponential backoff |
| 8 | `61b0ad6` | policies: AppArmor + SELinux confinement templates |
| 9 | `227a6d7` | ci: SBOM, dependabot, workflow permissions, CODEOWNERS, deny sweep |
| 10 | `8e9da3f` | release: sigstore signing + SLSA L3 provenance + scorecard CI |
| 11 | `6d842bd` | docs: CWE Top 25 (2024) documentary audit |
| 12 | `dd10e91` | fpe: bound the permutation cache at CACHE_MAX_ENTRIES (CWE-770) |
| 13 | `58caedc` | docs+ci: secure-development-policy + cargo-llvm-cov coverage |
| 14 | `8bc8f07` | fuzz+miri: cargo-fuzz scaffolding + miri CI job |
| 15 | `45705d0` | ci+docs: CodeQL SAST workflow + session handoff refresh |
| 16 | `6b35b49` | docs+ci: STRIDE threat model + weekly fuzz CI |
| 17 | `c1ccfe7` | ci: reproducible release-build verification job |
| 18 | `6932da5` | backup: explicit RestorePolicy for stale mapping archives |
| 19 | `39bec49` | wordlist: README + regression tests for invariants |
| 20 | `406f753` | readme: CI badges + security artifact index |
| 21 | `9b584ef` | supply-chain: cargo-vet bootstrap (config + imports) |
| 22 | `512f372` | fmt: rustfmt sweep over audit.rs + backup.rs |
| 23 | `898bd9b` | ci: cargo-vet job (soft-fail during bootstrap) |
| 24 | `1b11aa1` | cli: wire backup + restore subcommands through RestorePolicy |
| 25 | `00cd862` | scrambler: five example puzzles for the adversarial-LLM harness |
| 26 | `101c659` | todo: mark pre-session checked items |
| 27 | `c607770` | tests: two more regression tests on the rate-limit + sidecar path |
| 28 | `fab178c` | fmt: rustfmt sweep over the new backup CLI command |

28 commits.  All push targeted `claude/magical-turing-mele8c`.

---

## The original 12-item priority list

All 12 closed.

1. `SECURITY.md` / RFC 9116 — ✅ pre-session
2. Memory zeroization (`zeroize`) — ✅ pre-session
3. Constant-time comparison (`subtle`) — ✅ this session (`66a2daa`)
4. Daemon hardening — ✅ pre-session
5. `SAFETY:` comments — ✅ pre-session
6. HKDF (RFC 5869) — ✅ this session (`72efe9f`)
7. Vault unlock rate-limiting — ✅ this session (`d847283`)
8. Property tests + fuzz harness scaffolding — ✅ this session (`1b93a75`, `8bc8f07`)
9. SBOM generation in CI — ✅ this session (`227a6d7`)
10. Sigstore / cosign release-signing — ✅ this session (`8e9da3f`, with SLSA L3)
11. AppArmor / SELinux profile templates — ✅ this session (`61b0ad6`)
12. Ed25519 audit-log signing — ✅ this session (`4847e62`)

---

## Open follow-ups (next-session pickup queue)

### Code work (small / medium)
- Filesystem-side execution of the `RestorePolicy::RewrapToCurrent`
  rename plan (CLI `restore` currently prints the plan only — the
  bundle parsing, policy resolution, and rename list are wired)
- `cargo-vet` first-pass exemption backfill (run `cargo vet
  regenerate exemptions` on a clean tree, then flip the CI job's
  `continue-on-error` off)
- ns-helper privilege-chain ordering test (the CWE-269 audit walks
  the order; no programmatic test confirms refactors don't break it)
- Tokenizer benchmark — Claude tokenizer via count-tokens API; smaller
  open-weights tokenizers (Llama-3 SentencePiece, Mistral, Phi)
- Wordlist post-filter by tokenization density (v2 mapping change)

### Code work (larger)
- Background wordlist-permutation pre-build (needed for the rotation
  rate that defeats Threat B)
- Unified runtime-table wrapper (collapses rotation to one atomic
  table write)
- OverlayFS per-app writable upper layers
- O(N) bind cost at large manifest size

### Hardware-blocked
- FIDO2 wire-up
- TPM2 PCR-sealed backend
- TPM authorized policy
- tpm2-abrmd vs `/dev/tpm0` matrix
- Bare-metal NS validation pass

### Enterprise (separate private repo)
- Escrow backend, SIEM event sinks, console

### Process / GitHub-side
- Branch protection on `main` (cannot be set from this repo's source)
- OpenSSF Best Practices badge
- Expand CodeQL `language` matrix to include `rust` + `cpp` when
  upstream support stabilises

### Research (v2 / v3)
- Operator scrambling
- Whitespace-as-words
- Code-order scrambling with execution markers
- Junk-line / decoy-token injection
- Multi-language wordlists

---

## Key file map

```
crates/babbleon/src/
  audit.rs            — open_signed + verify_signed (Ed25519)
  backup.rs           — RestorePolicy + ResolvedRestore + resolve_against
  crypto.rs           — ct_eq() constant-time helper (NEW)
  enforcement/
    linux_ns.rs       — mount-namespace driver
    wrapper.rs        — unified shell template (CWE-78 audit clean)
    seccomp.rs        — block_process_inspection_syscalls()
    landlock.rs       — Landlock LSM sandbox
    response.rs       — ResponsePolicy + HoneyResponder
    ebpf.rs           — eBPF-LSM scaffold
    syscalls.rs       — ALL nix/libc kernel calls
  events.rs           — HoneyFifoReader with bounded read (CWE-400)
  mapping/
    kdf.rs            — HKDF-SHA-256 subkey derivation (NEW)
    mapper.rs         — uses kdf; is_honey → ct_eq; wordlist invariant tests
    fpe.rs            — uses kdf; Cache with FIFO eviction (CWE-770)
  vault/
    attempts.rs       — AttemptTracker, sidecar file, backoff (NEW)
    soft.rs           — Argon2id KEK
    usb.rs            — keyfile + optional passphrase
    fido2.rs          — skeleton; blocked on hardware
    tpm.rs            — skeleton; blocked on hardware
  process_hardening.rs — PR_SET_DUMPABLE / RLIMIT_CORE / mlockall
  session.rs          — unlock now rate-limit-gated

crates/babbleon/wordlist/
  words.txt           — 369652-word [a-z]+ wordlist
  README.md           — invariants (NEW)

crates/babbleon/tests/
  corpus_fingerprint.rs
  enforcement.rs
  fingerprint.rs
  mapping_properties.rs — 6 proptest properties (NEW)

docs/
  threat-model.md
  threat-model-stride.md          (NEW — STRIDE table)
  standards-survey.md
  operator.md
  cwe-top25-audit.md              (NEW)
  secure-development-policy.md    (NEW — SSDF mapping)
  verify-release.md               (NEW)

policies/                         (NEW)
  apparmor/usr.local.bin.babbleon
  selinux/{babbleon.te,.fc,.if}
  README.md

fuzz/                             (NEW)
  Cargo.toml
  README.md
  fuzz_targets/
    honey_fifo_line.rs
    fpe_roundtrip.rs
    wrapper_render.rs

supply-chain/                     (NEW — cargo-vet bootstrap)
  config.toml
  audits.toml
  exemptions.toml

.github/
  dependabot.yml                  (NEW)
  workflows/
    ci.yml                  (perms + SBOM + coverage + miri + reproducible)
    scorecard.yml                 (NEW)
    release.yml                   (NEW)
    codeql.yml                    (NEW)
    fuzz.yml                      (NEW)

CODEOWNERS                        (NEW)
deny.toml                         (tightened: unknown-git deny, RUSTSEC ignore)
README.md                         (badges + security artifact index)
```

---

## Git / branch hygiene

Push target this session: `claude/magical-turing-mele8c` only.

Repo stop-hook insists on `noreply@anthropic.com` as committer.
Every commit this session used
`-c user.name=Claude -c user.email=noreply@anthropic.com` to satisfy
that.

After each commit:
`git push origin HEAD:claude/magical-turing-mele8c`

---

## Live test status

128 tests across the workspace, all green.

- 111 lib unit tests
- 3 corpus-fingerprint integration tests
- 5 enforcement integration tests
- 4 fingerprint integration tests
- 6 mapping property tests
- 3 CLI unit tests

`cargo fmt --all --check`: clean.
`cargo clippy --workspace --all-targets -- -D warnings`: clean.
`cargo deny check`: `advisories ok, bans ok, licenses ok, sources ok`.

Coverage CI job (cargo-llvm-cov) lands the lcov on every push.
Miri CI job covers mapping / crypto / audit / vault::attempts.
CodeQL runs against the GH Actions workflows.
Reproducible-build job confirms `babbleon` + `babbleon-ns-helper`
byte-for-byte equal across two builds on the same runner.

Bare-metal validation still deferred until hardware arrives.
