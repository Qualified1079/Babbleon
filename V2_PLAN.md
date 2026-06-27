# Babbleon v2 — design plan

This document declares **Babbleon v1 deprecated for public release**
and lays out the ground-up redesign that becomes v2.  v1 stays in
the repository as a reference implementation and a test bed for the
ideas that v2 will productionise, but it does NOT ship as the public
product.

## Why v1 is not the public product

Three findings from the last few sessions, in increasing order of
severity:

1. **Identifier-only scramble is shape-defeated.** A model that knows
   it is looking at an Ubuntu host can fingerprint a file by its
   token-shape (twelve spaced terms → indent → two terms → indent
   → one term) without ever resolving an identifier.  The scramble
   defeats *lexical* recognition; it does not defeat *structural*
   recognition.  Once Babbleon is publicly known, attackers can
   prepare host-class structural fingerprints offline and adapt
   exploits at runtime without parsing the scrambled tokens at all.
   See `docs/v2/structure-scrambling.md` for the full analysis and
   the proposed v2 mechanism (wall-of-text + operator scrambling +
   code-order reorder + decoys + multilingual wordlists).

2. **Security conventions were bolted on rather than designed in.**
   v1 added zeroization, daemon hardening, constant-time compares,
   `SAFETY:` comments, `SECURITY.md`, and the standards survey
   *after* the architecture was set.  Many of them work in v1 but
   create awkward seams (e.g. `host_secret_hex: String` in
   `VaultPayload` — a serde-deserialized `String` cannot be made
   `Zeroizing` without a custom deserializer; we worked around it
   by zeroizing only the decoded bytes).  v2 will adopt
   `secrecy::SecretBox` everywhere from day one and reject any
   secret-holding type that does not zero on drop.

3. **The privilege model is over-broad.** `babbleon-ns-helper` is
   `4755 root:root` — full setuid-root for a setup that actually
   needs only three capabilities (`CAP_SYS_ADMIN`, `CAP_SETUID`,
   `CAP_IPC_LOCK`).  v2 will use file capabilities, not setuid, and
   will enforce least-privilege at every syscall site (see
   `docs/v2/least-privilege.md`).

## Goals carried from v1

Things v1 got right and v2 keeps verbatim or refines:

- Kerckhoffs: the per-host mapping is the only secret; everything
  else is public.
- Two-tier trust model (trusted view / untrusted view) enforced via
  Linux mount + PID namespaces.
- Per-host random bijective permutation via a Fisher-Yates shuffle
  seeded by HKDF over `(host_secret, epoch, purpose)`.
  (v1 uses hand-rolled `HMAC(secret || label)`; v2 switches to HKDF
  RFC 5869.)
- Honey tripwires (random honey names) AND stale-mapping tripwires
  (previous-epoch scrambled names).  Both still fire `HoneyTriggered`
  via a single FIFO; the responder model
  (NotifyOnly/KillTrigger/KillTriggerTree/Quarantine/SystemAlert)
  carries over.
- Tier detection via `/proc/self/ns/mnt` inode comparison against
  the trusted-NS inode written at session-open.
- seccomp deny-list for process-inspection syscalls (`ptrace`,
  `process_vm_readv`, `kcmp`, `pidfd_*`, `bpf`, `perf_event_open`,
  `userfaultfd`).
- Landlock LSM self-sandbox for the untrusted tier.
- Credential gate + env-var scrubber (exact-name + wildcard-suffix).
- Audit log SHA-256 hash chain, extended with Ed25519 per-entry
  signing in v2 (filed late in v1; lands by design in v2).
- Banner-spoofing wrapper template against fingerprint corpora.

## New in v2

The substantive additions:

### Structural scrambling (the big one)

See `docs/v2/structure-scrambling.md`.  Five composable layers:

1. **Identifier scramble** (v1 already does this).
2. **Operator scramble** — keywords (`if`, `def`, `return`, ...)
   become wordlist compounds.  Defeats "this is Python" recognition.
3. **Whitespace-as-words** — `\n`, ` `, `\t`, indent-open,
   indent-close become wordlist tokens drawn from a separate
   whitespace wordlist.  Source code becomes a wall of text;
   shape-fingerprint defence collapses because there *is* no shape.
4. **Code-order reorder with execution markers** — top-level
   blocks reordered; runtime preprocessor re-sequences before
   execution.
5. **Junk decoys** — ~70% of tokens are wordlist noise the
   preprocessor strips; ~30% is live code.  Attacker has to find
   the live code in a haystack per rotation.

Plus:

- **Multi-language wordlists** — EN/ES/FR/DE/JA/ZH/AR cycled per
  epoch.  Small effect on frontier models; meaningful on
  small-model tokenizers.

The runtime **preprocessor** is the new load-bearing component.
It runs only in the trusted tier (mnt-NS check), never writes
unscrambled source to disk (only pipes to the interpreter), has
its own seccomp profile and its own zeroize+mlock+no-coredump
hardening.

### Security conventions designed in from day one

See `docs/v2/security-baseline.md` (to be written next session).
Summary: `secrecy::SecretBox`/`Zeroizing` everywhere by default;
`subtle::ConstantTimeEq` for any secret-derived compare;
`#[forbid(unsafe_code)]` at the crate root with `unsafe`
quarantined to one syscall module per crate; HKDF instead of
hand-rolled domain separation; PR_SET_DUMPABLE / RLIMIT_CORE /
mlockall on startup before secrets enter memory.

### Least-privilege execution

See `docs/v2/least-privilege.md`.  Summary: no setuid-root binaries;
file capabilities only; each privileged operation runs in a
short-lived process that drops everything before its child exec.
Audit table of every syscall site that requires capability, the
specific capability required, and where in the program lifecycle
the capability is dropped.

### Naming conventions (locked in)

See `docs/v2/naming-conventions.md`.  The v1 audit-readability
rename pass (`mount_real_view`, `block_process_inspection_syscalls`,
`write_tripwire_script`, `fake_help_text_for`) was the right
discipline applied half-way through v1.  v2 adopts it from day
one; binaries, modules, functions, and types all carry names that
read as plain English statements of intent.  No undocumented
abbreviations.  No "ns-helper" type names.

### Standards alignment

See `docs/v2/standards-alignment.md`.  v1 surveyed five standards
(ASVS 5.0, SSDF v1.1, OpenSSF Scorecard, SLSA v1.0, CWE Top 25).
v2 additionally maps onto MITRE ATT&CK + D3FEND (essential for a
defensive tool), NIST SP 800-190 (container security — directly
relevant to namespace usage), NIST SP 800-207 (Zero Trust
Architecture), NIST CSF 2.0, in-toto + TUF (the substrate under
SLSA), CSAF 2.0 (advisory format), SARIF (SAST output), and a
chosen SBOM format (CycloneDX or SPDX — decision pending).

## Crate / binary names for v2

| v1 name | v2 name | Notes |
|---|---|---|
| `crates/babbleon` (lib) | `crates/babbleon-core` | Library only. |
| `crates/babbleon-cli` | `crates/babbleon` | The user-facing CLI keeps the bare name. |
| `crates/babbleon-ns-helper` | `crates/babbleon-launch-untrusted` | Verb-first, says what the operator does with it. |
| `crates/babbleon-pam` | `crates/babbleon-pam` | PAM ABI fixes the name. |
| n/a (new) | `crates/babbleon-preprocessor` | The runtime un-scrambler for v2 structural scrambling. |
| n/a (new) | `crates/babbleon-mapping-worker` | Separate-uid process that pre-builds the next epoch's permutation; communicates with the daemon over a one-shot pipe.  **NOTE (2026-06-26 night):** the in-process `PermutationCache` shipped in commit `31135f6` covers the steady-state cost the mapping-worker was originally proposed to solve.  The remaining motivation for a separate-uid worker is the *isolation* of the Fisher-Yates compute under a different uid (defense-in-depth against memory disclosure during the build), not the *cost* (now amortized).  Operator review can re-scope this crate around the isolation goal alone — likely much smaller than the original plan. |

## What stays in `crates/` from v1 unchanged

Nothing.  Every v1 crate gets a rewrite that runs through the v2
checklist: secrecy types, least-privilege syscall sites,
threat-model-first module docs, every `unsafe` carries a SAFETY
comment, HKDF for domain separation.

v1 is preserved at the tag `v1.0-reference` once v2 starts taking
shape, then v1 source is removed from `main` and lives only on
that tag.  The HTML scrambler harness and the two benchmarks
(`tools/{rotation,tokenizer}-benchmark/`) move forward verbatim
— they are measurement code, not product code.

## Phases

- **Phase 0 (now)** — design docs.  This document + the four
  under `docs/v2/`.  No code.
- **Phase 1** — v2 core crate skeleton.  `babbleon-core` with
  mapping, vault (HKDF, SecretBox), wrapper template, event bus.
  No structural scrambling yet — that's phase 3.  Identifier
  scramble + tripwires + response policy ported directly.
- **Phase 2** — v2 launcher + PAM.  `babbleon-launch-untrusted`
  with file capabilities, not setuid.  Per-syscall capability
  audit table in code comments.
- **Phase 3** — structural scrambling.  `babbleon-preprocessor`
  + operator scramble + whitespace-as-words + reorder markers +
  decoy injection.  This is where v2 earns its keep over v1.
- **Phase 4** — multi-language wordlists + density-tuned wordlist
  filter (from v1 RESEARCH T6 follow-ups).
- **Phase 5** — hardware backends (FIDO2, TPM) — the long-blocked
  v1 items.  These were stalled on hardware availability; pick
  back up when the test devices arrive.
- **Phase 6** — release engineering.  SLSA L3 reusable workflow,
  CycloneDX SBOM, cosign signing, AppArmor + SELinux profiles,
  STRIDE-formatted threat model doc.

Each phase ends with a STRIDE re-evaluation of the surface added
and a checklist sweep against the standards in
`docs/v2/standards-alignment.md`.

## What this means for v1 in the repo today

- v1 source stays put for now.  Existing TODOs against v1 are NOT
  cancelled — they remain useful inputs to v2 design.
- New v1 changes should be marked `[v1]` in their commit message
  prefix so v2 work is clearly distinct.
- The `magical-turing` branch keeps shipping incremental v1
  hardening (rate-limit, audit signing, fuzz, miri, CodeQL, etc.)
  because all of those will inform v2 design even if the v1
  *implementation* is not what ships publicly.
- Decision pending: does v2 develop on a separate branch, or in
  a `crates/v2-*` subtree of `main`?  Filed in
  `docs/v2/structure-scrambling.md` open questions.

---

For the substantive content, see:

- `docs/v2/structure-scrambling.md` — the technical heart of v2.
- `docs/v2/naming-conventions.md` — the discipline.
- `docs/v2/least-privilege.md` — privilege audit + v2 stance.
- `docs/v2/standards-alignment.md` — the survey gaps + v2 mapping.
- `docs/v2/security-baseline.md` (TBD next session) — the
  designed-in-from-day-one security conventions checklist.
