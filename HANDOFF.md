# Babbleon — Session Handoff

Branch (push target): `claude/magical-turing-mele8c`
Date: 2026-06-15
Last commit before this session: `80d37be` — honey response policy + stale-mapping tripwire

---

## Where the project sits

M3 (Linux namespace enforcement) and M3.5 (deception layer) are
shipped.  The two M3.5+ items that were filed against the original
"connected attacker" / Threat-B framing have landed in this branch:

- **Honey tripwire response policy** — `NotifyOnly` / `KillTrigger` /
  `KillTriggerTree`; PID-reuse-safe via `/proc/<ppid>/stat` start-time
  check; structured `HoneyTriggered` event carries `triggering_pid`
  and `triggering_pid_start`; operator opts in via
  `BABBLEON_HONEY_POLICY` env-var.  Default `NotifyOnly`.
- **Stale-mapping tripwire** — `Mapper::stale_names_for_previous_epochs`;
  CLI writes `/run/babbleon/stale.list`; wrapper template now has a
  `_is_stale` branch that fires `HoneyTriggered { source: "stale" }`
  via the FIFO.  Honey check runs first so a name in both lists
  classifies as honey (random-guess catcher wins ties).
  `STALE_RETAIN_EPOCHS = 8`.

81 tests across the workspace, all green.

The session before this one had restructured the threat model into
**two underlying threats** (A disconnected / B connected) with **four
expressions** (E1 solo internal, E2 solo external, E3 hybrid, E4
adversarial network of LLMs).  See `docs/threat-model.md`.

---

## What this overnight session is building

Operator gave a "build everything that's worth doing" instruction and
went to sleep.  The full list landed in TODO.md as a major addition
under **Security practices to land** and **Structure-level
scrambling — research**.  The shippable cluster, in priority order:

1. `SECURITY.md` / RFC 9116 — disclosure policy
2. Memory zeroization (`zeroize` crate) — wipe secrets on drop
3. Constant-time comparison (`subtle`) — for HMAC tag / MAC compares
4. Daemon hardening — `PR_SET_DUMPABLE`, `RLIMIT_CORE`, `mlockall`
5. `SAFETY:` comments on every `unsafe` block
6. HKDF (RFC 5869) replacing hand-rolled `HMAC(secret || label)`
7. Vault unlock rate-limiting with exponential backoff
8. Property tests + fuzz harness scaffolding
9. SBOM generation in CI
10. Sigstore / cosign release-signing scaffold
11. AppArmor / SELinux profile templates
12. Ed25519 audit-log signing

Operator also raised a structural-scrambling research line (operator
scrambling, whitespace-as-words, code-order with execution markers,
junk-line decoys, multi-language wordlists).  Recorded in TODO as
v2/v3 research; not built this session.

---

## What's NOT being done this session

- Anything that needs hardware (FIDO2, TPM, bare-metal NS validation)
- Anything that breaks API compatibility without an obvious migration
- The `tools/scrambler/example-puzzles/` deliverable (needs human
  curation of which puzzles to use)
- The structure-scrambling research line — fundamental design change,
  research write-up should precede code

---

## Key file map

```
crates/babbleon/src/
  enforcement/
    linux_ns.rs       — mount-namespace driver; mount_real_view, mount_scrambled_view
    wrapper.rs        — unified shell template with honey + stale branches
    seccomp.rs        — block_process_inspection_syscalls()
    landlock.rs       — Landlock LSM sandbox
    response.rs       — ResponsePolicy + HoneyResponder (NEW)
    ebpf.rs           — eBPF-LSM scaffold; kernel-gated at 6.1
    syscalls.rs       — ALL nix/libc kernel calls
  events.rs           — Event::HoneyTriggered { source, triggering_pid, ... }
  mapping/
    mapper.rs         — stale_names_for_previous_epochs (NEW)
  credentials.rs      — SCRUB_ENV_VARS + SCRUB_ENV_SUFFIXES (suffix matcher)
  audit.rs            — ChainedAuditLog (SHA-256 chain; Ed25519 signing pending)
  vault/
    soft.rs           — Argon2id KEK
    usb.rs            — keyfile + optional passphrase
    fido2.rs          — skeleton; blocked on hardware
    tpm.rs            — skeleton; blocked on hardware

tools/
  tokenizer-benchmark/  — measured ~1.07× compound-vs-spaced (cl100k/o200k)
  rotation-benchmark/   — measured 0.7 ms warm @ N=10; 24 ms warm @ N=100
  scrambler/            — HTML harness (example-puzzles/ TODO)
```

---

## Git / branch hygiene

Push target this session: `claude/magical-turing-mele8c` only.
`claude/awesome-pasteur-gmqg0o` is the local working branch; only
pushed when the operator explicitly asks.

The repo stop-hook insists on `noreply@anthropic.com` as committer.
After each commit, push with `git push origin
HEAD:claude/magical-turing-mele8c --force-with-lease`.

---

## Live test status (toolbox)

All 81 unit + integration tests pass.  Bare-metal validation deferred
until hardware arrives.
