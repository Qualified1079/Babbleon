# TODO — Ship Checklist

Concrete, ordered work items grouped by milestone. PLAN.md describes the
*architecture*; DEFERRED.md catalogs items punted with rationale; this
file is the **shippable list**. Check items off as they land.

Legend: `[ ]` open · `[x]` done · `[~]` in-progress · `(M?)` target milestone

---

## M1 — Sandbox demo (Rust) ✅

- [x] Workspace + 3 crates (`babbleon`, `babbleon-cli`, `babbleon-ns-helper`)
- [x] Fisher-Yates mapping over wordlist, seeded by HMAC-SHA-256(host_secret, epoch)
- [x] Vault: age + Argon2id soft backend; seal / unseal / rotate
- [x] Trusted / untrusted views; `SimulatedDriver` for no-syscall demo
- [x] Honey-name tripwires + `EventBus` with `StderrSink`
- [x] CLI: `init / unlock / rotate / trusted / untrusted / status / demo`
- [x] HTML scrambler harness (`tools/scrambler/`)

## M2 — Vault hardening

- [~] FIDO2 `get_assertion` flow (hmac-secret extension) — skeleton at
      `vault/fido2.rs`; returns `HardwareUnavailable` until M2 wires
      authenticator-rs behind `--features fido2`.
- [~] TPM2 PCR-sealed backend — skeleton at `vault/tpm.rs`; SEAL_PCRS=4,7,8,9;
      tss-esapi wiring deferred to M2.5 (see DEFERRED.md).
- [x] Argon2id second profile for headless/IoT (`Profile::Headless`,
      m=8 MiB, t=12); selectable via `Tier::SoftHeadless`.
- [x] Vault header schema version field (`VaultPayload.schema`); old vaults
      deserialize schema=0; migration path is re-seal.
- [x] USB-keyfile backend hardening tests: wrong-pw rejection, kek-uniqueness
      per keyfile, keyfile-only vs 2fa KDF differentiation (7 tests total)
- [x] `babbleon tpm-reseal` stub: exits 2, prints manual workaround + roadmap

## M3 — Linux namespace enforcement (the load-bearing piece)

- [x] `babbleon-ns-helper` setuid binary: `unshare(NEWNS|NEWPID)`, drop caps, `execve` driver
- [x] `LinuxNamespaceDriver`: bind-mount trusted/untrusted views into `/run/babbleon/scrambled`
- [x] `/proc` remount with `hidepid=2` inside untrusted PID NS
- [x] `pam_babbleon.so` (C shim — PAM ABI requires C) calling helper at session open
- [x] seccomp-bpf filter (deny `ptrace`, `process_vm_readv/writev`, `kcmp`, `pidfd_*`)
- [x] Landlock self-sandbox for untrusted tier (kernel 5.13+)
- [x] Wrapper trust-tier detection via `/proc/self/ns/mnt` inode comparison
- [x] Rotation cadence: systemd service + timer unit, installed by `babbleon install`
- [~] tini-as-PID-1 pattern — current ns-helper does its own reaper loop;
      good enough for M3, revisit if zombie reaping proves fiddly

## M3.5 — Deception layer

- [x] Banner deception table: `deception.rs` maps real→decoy tool; wrapper
      embeds decoy banner; untrusted `--help` returns `less`/`sort`/`date`
      text instead of silence. 3 tests enforce full coverage of DEFAULT_TRACKED.
- [x] Per-host SHA-256 padding in wrapper output — `enforcement/wrapper.rs`
      embeds HMAC(host_secret, scrambled_name)[0..16] in every wrapper script.
- [x] Adversarial fingerprint test vs ObserverWard / WhatWeb before ship

## M4 — Credential vault

- [x] Path-gated credential dirs (`credentials::discover` + `apply_untrusted_gate`)
- [x] IPC socket env-var deny-list (`SSH_AUTH_SOCK`, gpg-agent, DBUS, XDG_RUNTIME_DIR)
- [x] Env-var scrubber: deny-list from RESEARCH T8 (`credentials::scrub_env`)
- [x] Wire credential gate into `LinuxNamespaceDriver::present_untrusted`
      (reads `$HOME`; tmpfs-overlays each cred dir; count reported in EnforcementResult notes)
- [ ] OverlayFS per-app writable upper layers — deferred; tmpfs-overlay is the M4 default
- [x] CLI `babbleon credentials [--apply]` — dry-run lists + apply does live
      tmpfs gate (`credentials::apply_untrusted_gate`); Linux-only guard on apply

## M5 — Enterprise + escrow

- [x] Plugin registry seam (`plugins::PluginRegistry`) — enterprise crate registers
      `KekBackend` / `EnforcementDriver` / `EventSink` impls at startup
- [x] `JsonlFileSink` baseline audit sink (community-side)
- [x] Auditability: `audit::ChainedAuditLog` — SHA-256 hash chain; verify() detects
      truncation/tampering; reopening continues chain.
- [ ] Escrow backend (admin recovery) via separate KEK wrap — enterprise crate
- [ ] SIEM event sinks (Splunk HEC, syslog RFC5424, JSON-over-HTTPS) — enterprise crate
- [ ] Enterprise console (separate private repo; depends on public `babbleon` crate)

## Research track: LLM-driven install-time semantic diversification (v3+)

A natural successor / complement to Babbleon's runtime-name scrambling:
diversify the *implementation itself* per-device using a local code LLM.
Prior art: compiler-based MTD (ACM MTD workshops, 2014+), Polyverse
Polymorphic Linux (commercial since ~2017, compile-time ASLR-style binary
randomization), source-level "device diversity paradigm" papers.

What's new vs Polyverse: semantic AST-level rewrites (rename, control-flow
restructure, struct-field reorder, equivalent stdlib swap) instead of just
binary-layout randomization.  Forces the attacker to fingerprint each
function independently, not just defeat ASLR.

Shape (≤40B-param local model + tight harness):
- AST chunker (tree-sitter, one function per chunk).
- Mutation menu (~15 semantic-preserving transforms).
- Per-function test extractor + cargo/pytest sandbox.
- Property-test-gated infinite retry loop; fallback = keep original fn.
- Reproducer: pinned seed + model produces deterministic variant.
- Variant store at `.babbleon-variants/<file>.json` (seed → mutation log).

Resource math (single 4090/5090 + 32B-class coder):
- ~50-100 tok/s; 200k LOC ≈ 2M tokens; ~20-30 h fresh install,
  single-digit minutes incremental.  Matches Babbleon's weekly epoch cadence.

Privacy property is load-bearing here — sending source to a frontier API
to obfuscate against attackers is a weird threat model.  Local-only is the
honest pitch.

Out of scope for v1 Babbleon (M5+); track here as a research direction.

## Auditability / readability

- [ ] Rename pass: every public fn/type/module gets a name that says what it
      does in plain English, not what it's named after.  The runtime
      obfuscation is the product; the source code should be maximally
      readable so security auditors can verify the implementation is honest.
      Examples: `present_untrusted` → `mount_scrambled_view`,
      `apply_untrusted_filter` → `block_process_inspection_syscalls`,
      `write_honey_wrapper` → `write_tripwire_script`,
      `decoy_for` → `fake_help_text_for`.  Target: any function name should
      be guessable from its purpose without reading the code.
- [ ] Module-level doc comment pass: every file's top-of-file doc says
      WHY this module exists (what attack it defeats), not just WHAT it
      contains.  Threat-model-first comments make forks and downstream
      audits faster.

## Known leak: wrapper-size fingerprint

- [ ] Honey wrappers (~350B) and real-tool wrappers (~510B+) are
      distinguishable by `ls -la` alone — an attacker with read access to
      the scrambled dir can partition the set into "tripwire" vs
      "tracked tool" without executing anything.  Fix: pad every wrapper
      to a uniform size (e.g. 1024B) with shell-comment whitespace whose
      content is per-host HMAC bytes so the padding itself can't be
      stripped via a deterministic test.  Caught during live VM test
      2026-06-14.

## Cross-cutting / hygiene

- [x] CI: fmt + clippy + cargo-audit + cargo-deny (`.github/workflows/ci.yml`)
- [x] Reproducible release builds: `.cargo/config.toml` with musl static flags;
      `cargo build --release --target x86_64-unknown-linux-musl` produces a
      static binary with no glibc dep.
- [x] Operator docs (`docs/operator.md`): install, rotate, recover, decommission
- [x] Threat-model doc (`docs/threat-model.md`) with attacker capabilities table
- [x] Backup/restore: `backup::BackupBundle` — versions epoch + host_secret +
      tracked manifest + wordlist hash alongside any filesystem snapshot.
- [ ] macOS driver (Endpoint Security + Keychain) — explicit M5+ stretch
- [ ] Windows driver — research-only, v3+

---

For the *why* behind any deferred item, see `DEFERRED.md`.
For architectural rationale, see `PLAN.md`.
