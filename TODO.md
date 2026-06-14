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

- [ ] Banner deception table: scrambled `curl` returns plausible-wrong (`nano`-shaped) help
- [x] Per-host SHA-256 padding in wrapper output — `enforcement/wrapper.rs`
      embeds HMAC(host_secret, scrambled_name)[0..16] in every wrapper script.
- [ ] Adversarial fingerprint test vs ObserverWard / WhatWeb before ship

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
