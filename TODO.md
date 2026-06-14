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

- [ ] FIDO2 `get_assertion` flow (hmac-secret extension) — `crates/babbleon/src/vault/fido2.rs`
- [ ] TPM2 PCR-sealed backend via `tss-esapi` — `crates/babbleon/src/vault/tpm.rs`
- [ ] Argon2id second profile for headless/IoT (lower m, higher t); store profile in vault header
- [ ] Vault header schema version field; migration path
- [ ] USB-keyfile backend hardening tests (multi-authenticator matrix)
- [ ] `babbleon tpm-reseal` subcommand for kernel-update re-seal

## M3 — Linux namespace enforcement (the load-bearing piece)

- [ ] `babbleon-ns-helper` setuid binary: `unshare(NEWNS|NEWPID)`, drop caps, `execve` driver
- [ ] `LinuxNamespaceDriver`: bind-mount trusted/untrusted views into `/run/babbleon/<tier>`
- [ ] `/proc` remount with `hidepid=2,gid=proc` inside untrusted PID NS
- [ ] `pam_babbleon.so` (C shim — PAM ABI requires C) calling helper at session open
- [ ] seccomp-bpf filter (deny `ptrace`, `process_vm_readv/writev`, `kcmp`, `pidfd_*`)
- [ ] Landlock self-sandbox for untrusted tier (kernel 5.13+)
- [ ] Wrapper trust-tier detection via `/proc/self/ns/mnt` inode comparison
- [ ] Rotation cadence: systemd service + timer unit, installed by `babbleon install`
- [ ] tini-as-PID-1 pattern (avoid zombie-reaping issues with Rust at PID 1)

## M3.5 — Deception layer

- [ ] Banner deception table: scrambled `curl` returns plausible-wrong (`nano`-shaped) help
- [ ] Per-host SHA-256 padding in wrapper output (already designed)
- [ ] Adversarial fingerprint test vs ObserverWard / WhatWeb before ship

## M4 — Credential vault

- [ ] Path-gated credential dirs: `~/.aws`, `~/.ssh`, `~/.config/gh`, `~/.kube`, browser cookies
- [ ] IPC socket isolation: `SSH_AUTH_SOCK`, gpg-agent, `DBUS_SESSION_BUS_ADDRESS`, `XDG_RUNTIME_DIR`
- [ ] OverlayFS or per-app-bind credential layers (architecture decision needed)
- [ ] Env-var scrubber: deny-list from RESEARCH T8

## M5 — Enterprise + escrow

- [ ] Plugin registry: enterprise crate publishes `KekBackend` / `EnforcementDriver` / `EventSink` impls
- [ ] Escrow backend (admin recovery) via separate KEK wrap
- [ ] SIEM event sinks (Splunk HEC, syslog RFC5424, JSON-over-HTTPS)
- [ ] Enterprise console (separate private repo; depends on public `babbleon` crate)
- [ ] Auditability: signed event log; tamper-evident hash chain

## Cross-cutting / hygiene

- [ ] CI: clippy + cargo-deny + cargo-audit on push
- [ ] Reproducible release builds (musl static binaries)
- [ ] Operator docs (`docs/operator.md`): install, rotate, recover, decommission
- [ ] Threat-model doc with attacker capabilities table (drawn from RESEARCH T1-T16)
- [ ] Backup/restore tooling that's mapping-aware (epoch + wordlist version)
- [ ] macOS driver (Endpoint Security + Keychain) — explicit M5+ stretch
- [ ] Windows driver — research-only, v3+

---

For the *why* behind any deferred item, see `DEFERRED.md`.
For architectural rationale, see `PLAN.md`.
