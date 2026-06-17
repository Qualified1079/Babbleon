# Babbleon — Session Handoff

Branch (push target): `claude/magical-turing-mele8c`
Date: 2026-06-15
Last commit before this session: `a8351bd` — process_hardening: PR_SET_DUMPABLE + RLIMIT_CORE + mlockall

---

## Where the project sits

M3 (Linux namespace enforcement) and M3.5 (deception layer) shipped
before this session.  This overnight session worked top-to-bottom
through the 12-item security-practice priority cluster, plus the
follow-ups it surfaced (CWE Top 25 documentary audit, SSDF policy
doc, MAC profile templates, supply-chain hardening).

**Total tests: 128 across the workspace, all green.** (Was 81 at
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

22 commits.  All push targeted `claude/magical-turing-mele8c`.

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
- Wire the new `RestorePolicy` through the CLI's `restore` subcommand
  (the bundle structure is ready in `backup.rs`; CLI subcommand
  doesn't exist yet)
- `cargo-vet` first-pass exemption backfill (`cargo vet regenerate
  exemptions`) plus a CI gate
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

- 107 lib unit tests
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
