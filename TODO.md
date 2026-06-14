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
- [ ] Vault header schema version field; migration path
- [ ] USB-keyfile backend hardening tests (multi-authenticator matrix)
- [ ] `babbleon tpm-reseal` subcommand for kernel-update re-seal

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

- [ ] Banner deception table: scrambled `curl` returns plausible-wrong (`nano`-shaped) help
- [ ] Per-host SHA-256 padding in wrapper output (already designed)
- [ ] Adversarial fingerprint test vs ObserverWard / WhatWeb before ship

## M4 — Credential vault

- [x] Path-gated credential dirs (`credentials::discover` + `apply_untrusted_gate`)
- [x] IPC socket env-var deny-list (`SSH_AUTH_SOCK`, gpg-agent, DBUS, XDG_RUNTIME_DIR)
- [x] Env-var scrubber: deny-list from RESEARCH T8 (`credentials::scrub_env`)
- [ ] OverlayFS per-app writable upper layers (decision: tmpfs-over for M4 baseline,
      overlayfs only if apps need to actually *write* cred-shaped files)
- [ ] Wire credential gate into `LinuxNamespaceDriver::present_untrusted`
- [ ] CLI `babbleon credentials --apply` to invoke the gate (currently dry-run only)

## M5 — Enterprise + escrow

- [x] Plugin registry seam (`plugins::PluginRegistry`) — enterprise crate registers
      `KekBackend` / `EnforcementDriver` / `EventSink` impls at startup
- [x] `JsonlFileSink` baseline audit sink (community-side)
- [ ] Escrow backend (admin recovery) via separate KEK wrap — enterprise crate
- [ ] SIEM event sinks (Splunk HEC, syslog RFC5424, JSON-over-HTTPS) — enterprise crate
- [ ] Enterprise console (separate private repo; depends on public `babbleon` crate)
- [ ] Auditability: signed event log; tamper-evident hash chain (community-side)

## Cross-cutting / hygiene

- [x] CI: fmt + clippy + cargo-audit + cargo-deny (`.github/workflows/ci.yml`)
- [ ] Reproducible release builds (musl static binaries)
- [ ] Operator docs (`docs/operator.md`): install, rotate, recover, decommission
- [x] Threat-model doc (`docs/threat-model.md`) with attacker capabilities table
- [x] Tamper-evident audit log (`audit::ChainedAuditLog`) — SHA-256 hash chain;
      verify() detects truncation, in-place edits, and chain breaks.
- [ ] Backup/restore tooling that's mapping-aware (epoch + wordlist version)
- [ ] macOS driver (Endpoint Security + Keychain) — explicit M5+ stretch
- [ ] Windows driver — research-only, v3+

---

For the *why* behind any deferred item, see `DEFERRED.md`.
For architectural rationale, see `PLAN.md`.
