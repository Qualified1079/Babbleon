# Babbleon — Session Handoff

Branch (push target): `claude/magical-turing-mele8c` → soon
`v1-maintenance` per operator decision
Date: 2026-06-15 (evening — phase-1 build start)
Last commit before this session: `2b44f48` — v2 phase-0:
research-notes + decision recommendations

---

## Where the project sits

**v1 declared not-for-public-ship.**  Reasoning + design documented
across `V2_PLAN.md` and `docs/v2/*.md`.  v2 phase 0 (design docs)
is complete.

**Operator confirmed all five phase-0 decisions** (2026-06-15
afternoon, after research-backed recommendations landed in
`docs/v2/phase0-decisions.md`):

| # | Decision | Confirmed |
|---|---|---|
| 1 | Branch vs subtree | **Subtree** at `crates/v2-*` |
| 2 | File extension | **Keep `.py`** |
| 3 | Preprocessor topology | **Standalone binary** |
| 4 | v1 hardening branch | **Rename to `v1-maintenance`** |
| 5 | TEE direction | **v2.0 = developer + small-business; TEE in v3** |

**Also confirmed:**

- **Shipping plan:** GitHub releases with checkable checksums
  (already standard); plus a project website as a redundant
  distribution channel; plus expected downstream packaging by
  security vendors who license Babbleon under PolyForm
  Commercial terms (already-anticipated revenue path).
- **Open research filed but not blocking phase 1:**
  - Dynamic keyword extraction across languages (Python, Go, C,
    TypeScript, Rust, shell).  v2 layer 2 (operator scramble)
    wants language-agnostic operator detection — possibly via
    Tree-sitter grammars or LSP introspection.
  - Algorithmic derivation of per-role wordlist pool sizes.
    20k for direction markers was a back-of-envelope number;
    real sizing comes from an information-theoretic analysis
    parameterised by rotation rate and attacker work-factor
    target.  Provisional sizes in `docs/v2/phase0-research-notes.md`
    §11 are adequate; algorithmic derivation is a v2.0+ refinement.

---

## What this session is building

**Phase 1: v2 core crate skeleton.**  Per the recommendations:

- `crates/v2-babbleon-core/` library crate.
- `#[forbid(unsafe_code)]` at crate root.
- `secrecy::SecretBox` / `zeroize::Zeroizing` everywhere a secret
  byte lives.
- HKDF-SHA-256 (RFC 5869) for domain separation — replaces v1's
  hand-rolled `SHA256(host_secret || label)` and
  `HMAC(seed, purpose)`.
- `subtle::ConstantTimeEq` for any secret-derived compare.
- Plain-English naming throughout (`PerHostSecret`,
  `MappingBuilder`, `EpochMapping`, `Tripwire`, ...).
- Threat-model-first module docs.
- Differential tests that assert v2's identifier scramble matches
  v1's output for the same `(host_secret, epoch, tool)` triple —
  validates the port without regressing the threat model.

**Phase 1 deliverables (commit-by-commit):**

1. Workspace member + Cargo.toml + skeleton `lib.rs` with module map
2. `PerHostSecret` — secrecy-wrapped 32-byte secret with explicit
   construction / zeroize semantics
3. `key_derivation` — HKDF-SHA-256 sub-key derivation per
   (epoch, purpose) tuple
4. `permutation` — Fisher-Yates over wordlist seeded by HKDF;
   caching disabled in v2 (was a leak vector in v1 — see v1
   `mapping/fpe.rs` cache footnote)
5. `EpochMapping` (renamed from v1's `MappingTable`) + the
   `MappingBuilder` (renamed from `Mapper`)
6. Differential test against v1: same input → same scrambled output

After phase 1 mapping primitive lands, phase 1 continues with:

7. Wrapper template port (with v2 conventions applied)
8. Tripwire types + responder ported
9. Event bus + sinks ported (HoneyTriggered → `Tripwire` event)

Then phase 2 (launcher) and phase 3 (structural scrambling) per
`V2_PLAN.md`.

---

## What's NOT being done this session

- Any v1 source-code changes (v1 frozen at the current
  magical-turing tip; only doc / migration commits go to v1).
- The v1 → v1-maintenance branch rename (Anthropic-side
  session-naming question; operator confirmed the rename
  intent, but the mechanical rename happens out-of-band).
- Phase 3+ structural scrambling (need phase 1 + 2 first).
- Hardware backends (FIDO2, TPM) — still blocked.
- Dynamic keyword extraction research (filed; not blocking).
- Algorithmic pool-sizing analysis (filed; not blocking).
- Shipping infrastructure (website mirror, sec-vendor packaging
  templates) — phase 6.

---

## Key file map (v1 + v2 in transition)

```
V2_PLAN.md                          — vision + phase plan
HANDOFF.md                          — THIS doc
TODO.md                             — v1 + v2 work items

docs/                               — v1 docs (frozen)
  threat-model.md                   — v1 threat model
  standards-survey.md               — v1 standards gap analysis
  threat-model-stride.md
  cwe-top25-audit.md
  ...

docs/v2/                            — v2 design (phase 0 complete)
  structure-scrambling.md           — five-layer mechanism
  naming-conventions.md             — discipline
  least-privilege.md                — privilege audit
  standards-alignment.md            — missed-standards inventory
  obfuscation-landscape.md          — 7 additional layers + research
  phase0-research-notes.md          — 11 research threads
  phase0-decisions.md               — recommendations on 5 decisions

docs/v2/ (TBD next phase 0)
  threat-model.md                   — STRIDE + ATT&CK + D3FEND +
                                      800-190 + 800-207 maps
  security-baseline.md              — designed-in-day-one checklist
  attack-mapping.md                 — full traceability matrix

crates/                             — v1 source (frozen)
  babbleon/                         — v1 library
  babbleon-cli/                     — v1 CLI
  babbleon-ns-helper/               — v1 setuid helper
                                       (target rename:
                                        babbleon-launch-untrusted)
  babbleon-pam/                     — v1 PAM module

crates/v2-*                         — v2 source (this session)
  v2-babbleon-core/                 — phase 1 (in flight)
  v2-babbleon/                      — phase 1 CLI
  v2-babbleon-launch-untrusted/     — phase 2 (NOT setuid)
  v2-babbleon-pam/                  — phase 2
  v2-babbleon-preprocessor/         — phase 3 standalone binary
  v2-babbleon-mapping-worker/       — phase 3 separate-uid worker
```

---

## Git / branch hygiene

Push target this session: `claude/magical-turing-mele8c` only.
Operator confirmed the eventual rename to `v1-maintenance`; the
mechanical rename is out-of-band.

Repo stop-hook insists on `noreply@anthropic.com` as committer.
Use `-c user.name=Claude -c user.email=noreply@anthropic.com` on
every commit.

After each commit:
`git push origin HEAD:claude/magical-turing-mele8c`

---

## Live test status

Inherited: 128 tests across the v1 workspace, all green.
v2 phase 1 adds tests in `crates/v2-babbleon-core/`; running
`cargo test --workspace` covers both.

---

## Note for the parallel-session instance

If you pick this up after the current session ends:

- **Don't push to `magical-turing` with rebased / amended SHAs
  if other commits have landed in the meantime.**  Use
  `git fetch + git log HEAD..origin/...` to check before any
  force-push.
- **The HANDOFF + TODO updates in this commit are authoritative
  on operator decisions.**  Operator confirmed all five phase-0
  decisions; treat them as committed.
- **The dynamic-keyword + algorithmic-pool-sizing items are
  filed in TODO** but explicitly NOT blocking phase 1.  If you
  have spare cycles after the phase-1 mapping work lands, those
  are good next-up research items.
- **Phase 1's first deliverable is the mapping primitive
  (commits 1-6 listed in "What this session is building"
  above).**  Differential test against v1's output is the
  go/no-go for shipping phase 1.


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
