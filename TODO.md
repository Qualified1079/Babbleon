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

## Structure-level scrambling — research (v2 / v3 ideas)

The current scramble is *identifier-only*: tool names and credential
paths are renamed, but the *shape* of the host's code, configs, and
scripts is unchanged.  A model that knows it's looking at an Ubuntu
host (or any specific distro / framework) can fingerprint by code
*structure* — line shape, indentation, token-position patterns — and
then mechanically swap in the right exploit without ever having to
reason about the renamed identifiers.  Testing showed near-frontier
models cannot crack the scramble blind, but DO trivially defeat it
when given the original alongside.  Ideas to research and prototype:

- [ ] **Operator scrambling.**  Currently only identifiers are
      scrambled; keywords (`if`, `return`, `import`, `def`, etc.) are
      not.  Substituting them with wordlist tokens would lift the
      attacker's recognition layer from "I see Python control flow"
      to "I see a soup of unfamiliar tokens, some of which act like
      control flow."  Open question: which tokens are safe to remap
      (lexer-level vs parser-level), what the run-time un-substitute
      cost is, how this composes with the existing `--help`
      deception.
- [ ] **Whitespace-as-words.**  Replace literal whitespace (spaces,
      newlines, indentation) with wordlist tokens that the trusted-tier
      parser interprets as whitespace.  Source code becomes one
      continuous wall of words — no line boundaries, no indent
      structure — defeating the "shape-of-the-program" fingerprint
      entirely.  Cost: needs a thin runtime preprocessor for any
      script the user runs.  Useful only for scripts under Babbleon's
      control (cron, systemd, user-installed); not for binaries.
- [ ] **Code-order scrambling with execution markers.**  Permute the
      source order of code blocks; add markers the trusted-tier runner
      uses to reorder back at execution.  Defeats the "line N usually
      contains X" fingerprint that follows from idiomatic file
      ordering (imports first, helpers next, main last).  Composes
      with whitespace-as-words: the attacker sees neither shape nor
      sequence.
- [ ] **Junk-line / decoy-token injection.**  Sprinkle wordlist tokens
      that the trusted-tier runner strips before execution.  An
      attacker trying to insert a working exploit inside the
      ~250 ms rotation window must first locate the live code among
      the decoy noise.  Cost: increases parse time on the runner
      side; need to measure.
- [ ] **Multi-language wordlists.**  Cycle through wordlists from
      multiple natural languages (EN, ES, FR, DE, JA, ZH, AR, ...) per
      rotation, or mixed within a single rotation.  Hypothesis: LLM
      attention over a one-language scramble has a single attention
      head pattern; multi-language scramble fragments that pattern.
      Likely small effect because models reason in semantic space, not
      surface tokens — but cheap and the gain is non-zero.

These four are not for v1.  They reshape the threat model
substantially and deserve a research write-up of their own
(adversarial test against frontier models before committing).
Filed here so the line of thinking is recorded.

## Security practices to land (industry-standard, currently missing)

Triaged from a self-review against general secure-software practice.
"High leverage" = low effort, big credibility / safety win; "should-have"
= worth doing before any public release.

### High leverage — land first

- [ ] **`SECURITY.md` / RFC 9116 `security.txt`** at repo root.
      Declares the disclosure channel, supported versions, response
      SLA, and PGP key.  Standard for any security tool; its absence
      is a credibility smell on day one.
- [ ] **Memory zeroization of secrets via `zeroize`.**  `host_secret`,
      `KEK`, vault payload bytes, passphrase buffer all currently
      sit in `Vec<u8>` / `String` and are never wiped on drop.  Fix:
      `zeroize::Zeroizing<Vec<u8>>` (or `secrecy::SecretBox`)
      everywhere we hold key material.  Closes the core-dump /
      paged-out / heap-reuse leakage class.
- [ ] **Constant-time comparison for secret-derived bytes** via
      `subtle::ConstantTimeEq`.  Anywhere we `==`-compare HMAC tags,
      KEK material, FIDO2 response bytes, or vault MACs against
      attacker-supplied input we are variable-time.  Especially load
      bearing for the FIDO2 backend.
- [ ] **Daemon hardening: refuse core dumps, refuse swap.**  At
      startup the trusted-tier daemon (and the ns-helper) should call
      `prctl(PR_SET_DUMPABLE, 0)`, `setrlimit(RLIMIT_CORE, 0)`, and
      `mlockall(MCL_CURRENT | MCL_FUTURE)` (gated on
      `RLIMIT_MEMLOCK`).  Closes the swap- and core-dump-leak class.
- [ ] **`SAFETY:` comments on every `unsafe` block.**  We have
      several (`libc::kill`, `libc::mkfifo`, the BPF probe).  Each
      needs a one-line comment naming the invariants the caller
      relies on.  Trivial; matters at audit time.

### Crypto hygiene

- [ ] **HKDF-SHA-256 (RFC 5869) for domain separation** instead of
      hand-rolled HMAC-of-purpose-string.  Replace `Mapper::purpose_seed`
      (`SHA256(host_secret || label)`) and the per-purpose HMAC paths
      with `hkdf::Hkdf<Sha256>` using explicit `salt` / `info` /
      `length`.  Same security properties; auditor-recognizable.
- [ ] **Rate-limiting on vault unlock attempts.**  Vault header
      carries an attempt counter; increments before each KDF, clears
      on success; exponential backoff after 3 failures; lock-out at
      10 attempts requiring recovery key.  RESEARCH T5 flagged this;
      not yet shipped.

### Supply-chain + build integrity

- [ ] **SLSA provenance + sigstore/cosign signing of release
      artifacts.**  `cosign sign-blob` over each release tarball;
      attestation logged to Rekor; verification documented for users.
      Currently a release is just an unsigned tarball.
- [ ] **SBOM generation in CycloneDX or SPDX**, generated by
      `cargo cyclonedx` (or similar) and shipped with releases.
      Required by federal / enterprise procurement post-2024.
- [ ] **`cargo-vet` for transitive-dep audits** alongside the existing
      `cargo-deny` / `cargo-audit`.  Addresses xz-class supply-chain
      attacks that vulnerability databases miss because the attack is
      in not-yet-disclosed code.
- [ ] **Reproducible-build verification CI job.**  Build twice on
      different runners and `cmp` the artifacts.  Operator docs claim
      musl-static reproducibility; nothing currently confirms the
      bytes are deterministic.

### Testing

- [ ] **`cargo-fuzz` on three surfaces:**
      - Honey-FIFO JSON parser — defence-in-depth even though we own
        the wrapper that writes the JSON.
      - FPE permutation roundtrip — property: encrypt-then-decrypt
        is identity for any valid input.
      - Wrapper-template renderer — property: no field substitution
        can produce shell-injectable output.
- [ ] **`proptest` / `quickcheck` on mapping bijection.**  Property:
      `build_table` over any tracked list of N tools produces N
      unique scrambled names (collision-freeness as a property, not
      a single example).
- [ ] **`miri` runs in CI** to catch UB in unsafe-libc blocks.

### Audit-log integrity

- [ ] **Ed25519-sign each `ChainedAuditLog` entry** in addition to
      the SHA-256 hash chain.  Today an attacker who roots the box
      can rewrite the entire chain; with a signing key held off-host
      (or in a TPM), tampering is detect-but-not-tamper-without-
      being-noticed.  Standard pattern for tamper-evident logs.

### OS-level profile templates

- [ ] **AppArmor profile** template for `babbleon` and
      `babbleon-ns-helper`.  Even a permissive template that
      operators can tighten is better than nothing.
- [ ] **SELinux policy module** template covering the setuid helper
      and the credential-gate mount syscalls.

### Compliance / publication signals

- [ ] **OpenSSF Best Practices badge** (Linux Foundation).  Checklist
      exercise; gives the project a visible "we follow basic practice"
      signal.  Cheap to claim once the items above land.
- [ ] **OpenSSF Scorecard** running in CI; expose the score in
      README.
- [ ] **CodeQL or Semgrep SAST** in CI.  Catches the classes of bug
      that clippy + cargo-audit don't.
- [ ] **STRIDE-formatted threat model.**  We have a threat-model doc;
      it's not formatted as STRIDE / data-flow diagrams.  Industry
      procurement expects STRIDE for any security-claiming product.
- [ ] **`CODEOWNERS`** at repo root.  Defines who must review which
      paths; required by branch protection for any meaningful "two
      reviewers required" policy.

### Standards survey to complete

- [ ] **Confirm against OWASP ASVS 5.0** (released May 2025) — the
      350-requirement, 17-category standard for application security
      verification.  ASVS 5.0 modernizes for cloud-native
      architectures and adds clearer crypto / supply-chain controls.
      Map Babbleon's design + tests onto ASVS controls; identify
      gaps.  See `https://github.com/OWASP/ASVS`.
- [ ] **Confirm against NIST SP 800-218 (SSDF v1.1)** secure software
      development practices, especially the PO/PS/PW/RV practice
      families and the supply-chain integrity profile.  Required
      reading for any federal procurement path.
- [ ] **Confirm against CWE Top 25** — make sure none of the Top 25
      weakness classes have an obvious presence in the current code.
- [ ] **Confirm against the SLSA v1.0 build levels** — current build
      sits at SLSA L0; target L2 (hosted CI with provenance) for v1
      release and L3 (hardened builder) for v2.

These four standards-survey items were going to be covered by a web
search in this session; session limit was hit before the survey
completed.  Resume against the live documents.

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
