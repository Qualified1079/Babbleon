# TODO — Ship Checklist

Concrete work items grouped by milestone.  PLAN.md describes the
*architecture*; docs/threat-model.md names what we defend against;
this file is the **shippable list with rationale inline**.

Legend: `[ ]` open · `[x]` done · `[~]` in-progress · `(blocked)` —
blocked on something external

When an item is non-trivial, the explanation lives directly under
the checkbox.  Once-deferred items that have landed are marked `[x]`
and kept for audit history; truly historical ones move to commit
messages.

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

- [~] FIDO2 `get_assertion` flow (hmac-secret extension) — `(blocked on hardware)`
      Skeleton at `crates/babbleon/src/vault/fido2.rs`; returns
      `HardwareUnavailable`.  Need authenticator-rs
      `PublicKeyCredentialRequestOptions` wiring behind `--features
      fido2`, PIN handling, user-presence prompt, origin/rp_id wiring,
      and a multi-authenticator test matrix (YubiKey 5, Solokey,
      OnlyKey — extension support varies).
- [~] TPM2 PCR-sealed backend — `(blocked on hardware)`
      Skeleton at `crates/babbleon/src/vault/tpm.rs`; `SEAL_PCRS=4,7,8,9`;
      tss-esapi wiring deferred to M2.5.
- [ ] TPM authorized policy for post-kernel-update re-seal — `(blocked on hardware)`
      After a kernel update, PCR 8/9 values change; the sealed blob
      becomes unreadable.  Production path: `tpm2_policyauthorize`
      with a signing key that lets the admin issue new PCR policies
      without re-sealing the KEK.  Current stub `babbleon tpm-reseal`
      exits 2 with manual instructions.
- [ ] tpm2-abrmd vs `/dev/tpm0` test matrix — `(blocked on hardware)`
      Resource manager behaviour differs between distros and kernel
      versions.  Matrix required before ship.
- [x] Argon2id second profile for headless/IoT (`Profile::Headless`, m=8 MiB, t=12)
- [x] Vault header schema version field (`VaultPayload.schema`)
- [x] USB-keyfile backend hardening tests (7 tests total)
- [x] `babbleon tpm-reseal` stub: exits 2, prints manual workaround + roadmap

### Architectural decisions, recorded so they aren't silently reversed

- **USB keyfile path is caller-supplied, never stored in vault.**  Storing
  it for UX convenience would leak unencrypted metadata.  Decision
  documented in `docs/operator.md`.

## M3 — Linux namespace enforcement

- [x] `babbleon-ns-helper` setuid binary: `unshare(NEWNS|NEWPID)`, drop caps, `execve` driver
- [x] `LinuxNamespaceDriver`: bind-mount trusted/untrusted views into `/run/babbleon/scrambled`
- [x] `/proc` remount with `hidepid=2` inside untrusted PID NS
- [x] `pam_babbleon.so` (C shim — PAM ABI requires C) calling helper at session open
- [x] seccomp-bpf filter (deny `ptrace`, `process_vm_readv/writev`, `kcmp`, `pidfd_*`)
- [x] Landlock self-sandbox for untrusted tier (kernel 5.13+)
- [x] Wrapper trust-tier detection via `/proc/self/ns/mnt` inode comparison
- [x] Rotation cadence: systemd service + timer unit, installed by `babbleon install`
- [~] tini-as-PID-1 pattern — current ns-helper does its own reaper loop;
      good enough for M3, revisit if zombie reaping proves fiddly.
- [ ] Bare-metal validation pass — `(blocked on hardware)`
      `make_root_private()`, `hidepid=2` with real PID NS, full setuid
      ns-helper path, end-to-end PAM session integration.  All work in
      principle; need bare-metal Fedora Silverblue (not toolbox/podman)
      to confirm.

## M3.5 — Deception layer

- [x] Banner deception table: `deception.rs` maps real→decoy tool
- [x] Per-host SHA-256 padding in wrapper output
- [x] Adversarial fingerprint test vs captured real-tool `--help` corpora
      (`tests/corpus_fingerprint.rs`)
- [x] Wrapper-size fingerprint leak — fixed via unified template
- [x] **Honey tripwire response policy** —
      `crates/babbleon/src/enforcement/response.rs`.  `ResponsePolicy`
      enum with `NotifyOnly` (default) · `KillTrigger` (SIGKILL the
      wrapper's PPID, with /proc start-time check to defeat PID
      reuse) · `KillTriggerTree` (`kill -KILL -<pgid>`).  Wrapper
      template now captures PPID + start-time and tags FIFO output
      with `source`.  `HoneyTriggered` event carries structured
      `triggering_pid` / `triggering_pid_start`.  Operator selects via
      `BABBLEON_HONEY_POLICY` env-var.  Quarantine + SystemAlert filed
      as M3.5+++ follow-ups (need cgroup / PAM integration).
- [x] **Stale-mapping tripwire** —
      `crates/babbleon/src/mapping/mapper.rs` + wrapper template +
      CLI.  `Mapper::stale_names_for_previous_epochs(tracked, epoch,
      STALE_RETAIN_EPOCHS=8)` returns scrambled names from previous
      epochs; CLI writes `/run/babbleon/stale.list`; wrapper template
      checks the list and fires `HoneyTriggered { source: Stale }`
      via FIFO.  Honey match takes precedence over stale when both
      lists contain a name (random-guess catcher wins ties).
- [ ] **Background wordlist-permutation pre-build.**
      `crates/babbleon/src/mapping/fpe.rs`.  Each fresh epoch costs
      ~18 ms Fisher-Yates over the 370k-word permutation
      (`tools/rotation-benchmark/RESULTS.md`).  Pre-build epoch+1 in
      background → next rotation tick is a cache hit (~0.2 ms).
      Required for the rotation rate that defeats Threat B
      (connected-attacker; E3 hybrid, E4 swarm).
      **Read leakiness mitigations before implementing**:
      - *Process memory.*  Pre-built permutation IS the next mapping;
        a memory read on the daemon recovers it.  Run pre-build in a
        separate-uid worker with its own seccomp; transfer the
        activated table over a one-shot pipe at rotation tick; never
        share an address space with the active daemon.
      - *Cache + branch-predictor side channels.*  Fisher-Yates over
        370k entries has a predictable access pattern; a co-tenant
        adversary can extract bits.  Either build under a
        data-independent shuffle variant, or accept the leak and
        shorten pre-built table lifetime.
      - *Disk / swap.*  `mlock` the working region; refuse to pre-build
        if `RLIMIT_MEMLOCK` is too small.
      Reference safe-but-slower design: separate process, pipe-only
      handoff at rotation tick, locked working set, exits per tick.
- [ ] **Unified runtime-table wrapper.**
      `crates/babbleon/src/enforcement/wrapper.rs`.  Today each
      rotation re-renders one shell script per tracked tool (~0.4 ms
      each, dominates rotation cost above N≈100).  A single wrapper
      binary that reads its scrambled name from a runtime table file
      collapses rotation to one atomic table write.  Combined with the
      perm pre-build above, enables millisecond-class rotation.

## M4 — Credential vault

- [x] Path-gated credential dirs (`credentials::discover` + `apply_untrusted_gate`)
- [x] IPC socket env-var deny-list (`SSH_AUTH_SOCK`, gpg-agent, DBUS, XDG_RUNTIME_DIR)
- [x] Env-var scrubber: exact-name deny-list + wildcard-suffix filter
      (`*_TOKEN` / `*_SECRET` / `*_KEY` / etc.); includes AI-SDK family
      (Anthropic, OpenAI, HF, Mistral, Cohere, ...).
- [x] Wire credential gate into `LinuxNamespaceDriver::mount_scrambled_view`
- [x] CLI `babbleon credentials [--apply]`
- [ ] **OverlayFS per-app writable upper layers.**
      `crates/babbleon/src/credentials.rs`.  Shipped credential gate
      uses a tmpfs overlay per cred dir.  Per-app writable upper layer
      via overlayfs would let untrusted-tier processes make local
      edits without contaminating the trusted view.  Architecture
      TBD: overlayfs vs bind-mount-per-app.
- [ ] **O(N) bind cost at large manifest size.**
      `crates/babbleon/src/enforcement/linux_ns.rs`.  At N=200 tools
      per mount cycle ≈ 50 ms; at N=2000 (enterprise scale) revisit.
      Options: FUSE overlay; bind a single pre-prepared directory
      tree; OverlayFS lowerdir union.

## M5 — Enterprise (separate private repo)

- [x] Plugin registry seam (`plugins::PluginRegistry`)
- [x] `JsonlFileSink` baseline audit sink (community-side)
- [x] `audit::ChainedAuditLog` — SHA-256 hash chain
- [ ] Escrow backend (admin recovery) via separate KEK wrap
- [ ] SIEM event sinks (Splunk HEC, syslog RFC5424, JSON-over-HTTPS)
- [ ] Enterprise console (depends on public `babbleon` crate)

## Auditability / readability

- [x] Rename pass for plain-English public APIs
- [x] Threat-model-first module doc headers across `enforcement/`

## Benchmarks + measurements (data, not advertising)

- [x] `tools/tokenizer-benchmark/` — measures BPE token cost for
      compound names vs spaced English.  Result: ~1.07× on cl100k /
      o200k.  Not load-bearing; kept around as data.
- [x] `tools/rotation-benchmark/` — measures userspace rotation cost
      (cold and warm paths) as a function of tracked-tool count.
- [ ] **Tokenizer benchmark — smaller-model tokenizers.**
      The 1.07× result is for OpenAI's near-frontier tokenizers; smaller
      open-weights tokenizers (Llama-3 SentencePiece, Mistral, Phi)
      plausibly show superlinear penalty.  Hypothesis, not measurement.
      Run via the existing harness once SentencePiece bindings are
      added.
- [ ] **Tokenizer benchmark — Claude tokenizer.**  Via the
      count-tokens API.  Single number; cheap.
- [ ] **Wordlist post-filter by tokenization density.**  v2 mapping
      change: pick wordlist entries that score in the mid-tail of
      cl100k/o200k token density.  Probably small empirical benefit,
      worth prototyping before committing.

## HTML scrambler

- [x] `tools/scrambler/index.html` — standalone harness (417 lines, complete)
- [ ] **`tools/scrambler/example-puzzles/`** — directory exists but is
      empty; user wants to run an adversarial-LLM simulation against
      scrambled Python puzzles.  Pick / write the puzzle set.

## Cross-cutting / hygiene

- [x] CI: fmt + clippy + cargo-audit + cargo-deny
- [x] Reproducible release builds: musl static
- [x] Operator docs (`docs/operator.md`)
- [x] Threat-model doc (`docs/threat-model.md`)
- [x] Backup/restore: `backup::BackupBundle`
- [ ] **Backup/restore policy for stale mapping archives.**
      `crates/babbleon/src/backup.rs`.  Restoring an old snapshot
      needs an explicit policy: re-seal under the current mapping, or
      honour the snapshot's mapping until next rotation?  No policy
      yet; current behaviour is implicit re-seal on restore.

## Documented limitations (composed defenses, NOT future TODOs)

These three are honestly out of Babbleon's reach by design.  They are
NOT items to build; they are items to document and to leave to
adjacent layers.  Listed so a fork doesn't quietly try to "fix" them.

- **L1. Built-in / direct syscall bypass.**  Python/Node/PHP/Ruby/Go
  runtimes carry their own networking and filesystem libs; namespace
  renames don't reach in.  Defense composes with host firewall +
  Landlock/AppArmor.
- **L2. Bring Your Own Environment (BYOE).**  Static busybox-class
  payloads run regardless of what we rename.  Credential gating and
  tripwires reduce what they can accomplish on the host (primitives
  without knowledge).
- **L3. Shared-library leak via `/proc/self/maps`.**  `ld-linux.so` /
  `libc.so.6` must be reachable at canonical paths.  Documented as a
  fingerprint surface, not a key-recovery channel.  Designs that try
  to obfuscate libc are vetoed.

See `docs/threat-model.md` for the full discussion.

## Platform expansion (out-of-scope this year)

- [ ] macOS driver — Endpoint Security framework + FUSE (sandbox demo
      only) + Keychain / Secure Enclave.  M5+ stretch.
- [ ] Windows driver — minifilter for the namespace-equivalent piece;
      research-only stage, v3+.

---

For architectural rationale, see `PLAN.md`.
For threat model and defended-against attacker capabilities, see
`docs/threat-model.md`.
