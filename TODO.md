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
- [x] **Constant-time comparison for secret-derived bytes** via
      `subtle::ConstantTimeEq`.  `crates/babbleon/src/crypto.rs` exposes
      `ct_eq(&[u8], &[u8]) -> bool`; `MappingTable::is_honey` now uses
      it (full traversal, no early-exit) so neither the matching index
      nor the no-match outcome is leakable by timing.  Pattern set up
      for FIDO2 / Ed25519 sites where comparison against attacker input
      is load-bearing.
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

- [x] **HKDF-SHA-256 (RFC 5869) for domain separation** instead of
      hand-rolled HMAC-of-purpose-string.  `crates/babbleon/src/mapping/kdf.rs`
      now wraps `hkdf::Hkdf<Sha256>` with a fixed salt
      `b"babbleon-hkdf-v1"`; `Mapper::purpose_seed` and
      `fpe::derive_chacha_seed` both call through it.  The `hmac` direct
      dep was dropped from `babbleon/Cargo.toml` (still pulled in
      transitively by `hkdf`).  Same security properties as before for a
      32-byte uniformly random `ikm`; the win is auditor-recognizable
      shape (explicit `salt` / `info` / `len`).
- [x] **Rate-limiting on vault unlock attempts.**
      `crates/babbleon/src/vault/attempts.rs` exposes `AttemptTracker`
      backed by a sidecar file at `<vault>.attempts` (JSON, 0o600).
      First `INSTA_RETRIES = 3` failures are immediate (typo budget);
      then exponential backoff `2^(n-3)` seconds capped at 60 s; at
      `LOCKOUT_AT = 10` consecutive failures further attempts are
      refused with `BabbleonError::UnlockLockedOut`.  Check runs *before*
      the Argon2id KDF so a brute-force attacker can't burn CPU on
      refused attempts.  Wired into `Session::unlock` and cleared on
      `Session::initialize`.  Sidecar parse errors default to "fresh
      state" — defence-in-depth, not a hard correctness boundary.

### Supply-chain + build integrity

- [x] **SLSA provenance + sigstore/cosign signing of release
      artifacts.**  `.github/workflows/release.yml` ships a tag-
      triggered workflow that: builds x86_64-linux-musl static
      binaries, generates a per-release CycloneDX SBOM, keyless-signs
      both with cosign (workflow OIDC identity, no long-lived
      secrets), runs the official SLSA generator
      (`slsa-framework/slsa-github-generator` v2.0.0) for L3
      provenance, and attaches everything to a draft GitHub Release.
      Verification flow in `docs/verify-release.md`.
- [x] **SBOM generation in CycloneDX or SPDX.**  `.github/workflows/ci.yml`
      gained an `sbom` job that runs `cargo cyclonedx --format json`
      and uploads `babbleon-sbom*.cdx.json` as a 90-day artifact on
      every push.  Release-attached SBOMs land with the sigstore
      signing work below.
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
- [x] **`proptest` / `quickcheck` on mapping bijection.**
      `crates/babbleon/tests/mapping_properties.rs` covers six
      properties at 16 cases each (each `build_table` cold-builds the
      370k-entry permutation, so case-count is wall-clock-bound):
      bijection (no collisions, scramble∘reveal = id), honey
      disjointness, determinism, secret separation, FPE round-trip,
      and rotation moves every entry.  Full property suite runs in
      ~56 s.
- [ ] **`miri` runs in CI** to catch UB in unsafe-libc blocks.

### Audit-log integrity

- [x] **Ed25519-sign each `ChainedAuditLog` entry** in addition to
      the SHA-256 hash chain.  `ChainedAuditLog::open_signed(path,
      signing_key)` + `verify_signed(path, &verifying_key)`; signature
      covers the JSON form of `{prev, seq, ts, event}` (a separate
      `SigningPayload` type so the signing bytes are exactly what the
      verifier reconstructs).  Signed mode rejects unsigned entries —
      a post-compromise attacker who appends with the chain-only path
      gets caught.  Backward-compatible: chain-only `verify` still works
      against signed logs (SIEM forwarders don't need the public key).
      Operator UX (where to put the signing key — TPM, escrow host,
      sidecar file) is filed as a follow-up.

### OS-level profile templates

- [x] **AppArmor profile** template for `babbleon` and
      `babbleon-ns-helper`.  `policies/apparmor/usr.local.bin.babbleon`
      with explicit allow paths for vault/runtime/CLI state, denials
      for shadow/sudoers/sys_admin/sys_module/dac_override, and a
      nested `ns-helper` child profile that briefly holds CAP_SYS_ADMIN
      for `unshare`.  Install instructions in `policies/README.md`.
- [x] **SELinux policy module** template covering the setuid helper
      and the credential-gate mount syscalls.  `policies/selinux/`
      has `babbleon.te` (two domains — `babbleon_t` and
      `babbleon_ns_helper_t` — with auto-transition between them),
      `babbleon.fc` (file-context labels for the binaries, runtime,
      vault), and `babbleon.if` (callable interfaces for other
      modules).  `neverallow` lines record the hard exclusions
      (sys_module, sys_ptrace).

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
- [x] **`CODEOWNERS`** at repo root.  Carves out per-path owners for
      crypto/vault/audit/setuid/CI/policy/docs surfaces above the repo-
      wide default.  Required by branch protection for any meaningful
      "two reviewers required" policy.

### Standards survey

- [x] **Survey completed** — see `docs/standards-survey.md`.  Maps
      Babbleon against OWASP ASVS 5.0 (17 chapters, ~350 reqs), NIST
      SSDF v1.1 (PO/PS/PW/RV families), OpenSSF Scorecard (20 active
      checks), SLSA v1.0 (L0–L3 build levels), and CWE Top 25 (2024
      ranked list).  Gap items below are taken from that survey.

### From the standards survey — SSDF / Scorecard

- [x] **`docs/secure-development-policy.md`** — explicit policy doc
      covering branch protection, required reviewers, allowed crates,
      dependency-update cadence, release-signing procedure, and a
      practice→artifact mapping table.  Covers SSDF PO/PS/PW/RV families.
- [x] **`cargo-llvm-cov`** coverage measured in CI.
      `.github/workflows/ci.yml` `coverage` job runs
      `cargo llvm-cov --workspace --lcov` (property suite excluded to
      keep wall-clock under 5 min) and uploads `lcov.info` as a 30-day
      artifact.  Maps to SSDF PW.8.1.
- [x] **`cargo-deny` policy sweep** — `deny.toml` now: `yanked = "deny"`
      (was already set), explicit `unknown-git = "deny"` + empty
      `allow-git = []` (releases must come from crates.io), permissive
      license allow-list, and an explicit ignore for the pre-existing
      `proc-macro-error` advisory (RUSTSEC-2024-0370) with a roadmap
      pointer.  `cargo deny check` reports `advisories ok, bans ok,
      licenses ok, sources ok`.
- [ ] **Enable branch protection on the remote** — require PR
      review, require status checks pass, no force-push to main,
      signed commits required.  Scorecard Branch-Protection check.
      *(Remote-side action; cannot be set from this repo's source.)*
- [x] **Configure Dependabot** — `.github/dependabot.yml` ships a
      weekly cadence on `cargo` + `github-actions` ecosystems with a
      grouped update for the crypto-crate patch+minor train.
- [x] **Audit `.github/workflows/*.yml` for explicit `permissions:`
      blocks.**  `ci.yml` now has a workflow-level `permissions:
      contents: read` plus an explicit per-job restatement; every job
      runs read-only against `GITHUB_TOKEN`.  Scorecard Token-
      Permissions should now report green.
- [x] **Run Scorecard against the repo** as a scheduled CI workflow
      and publish the score in README.  `.github/workflows/scorecard.yml`
      runs weekly + on branch-protection-rule changes + on push to
      `main`; uploads SARIF to the GitHub code-scanning dashboard.
      README badge is filed for the first run (needs the public
      Scorecard repo ID).

### From the standards survey — SLSA

- [x] **SLSA L2 release workflow.** (Subsumed below — landed at L3
      directly via the reusable generator.)
- [x] **`docs/verify-release.md`** with the `cosign` + `slsa-verifier`
      commands users run to verify the signature, provenance, and SBOM.
- [x] **SLSA L3 target** — landed in `.github/workflows/release.yml`
      via `slsa-framework/slsa-github-generator@v2.0.0`'s reusable
      generic generator (L3-conformant on GitHub-hosted runners).

### From the standards survey — CWE Top 25 audit

Full audit lives in `docs/cwe-top25-audit.md`.  Per-item status:

- [x] **CWE-22 documentary audit** on wrapper-path construction.
      Scrambled names are HMAC-output compounds drawn from a static
      `[a-z]`-filtered wordlist; no path-separator byte can appear.
- [x] **CWE-78 / 77 / 94 wrapper-renderer audit.**  Decoy banner uses
      single-quote escape; real_path lands behind shell double-quote;
      remaining fields are alphanumeric or numeric.  Fuzz target on
      the renderer is filed below.
- [x] **CWE-400 length-bounded honey-FIFO reader.**
      `crates/babbleon/src/events.rs`.  `HoneyFifoReader::run` now reads
      lines through a `Take` adapter capped at `MAX_HONEY_LINE_BYTES`
      (16 KiB).  Over-limit lines are dropped and the reader resyncs to
      the next newline via `discard_to_newline`.  Wrapper produces
      ~150-byte lines; 16 KiB gives 100× headroom and stays well below
      page-allocation cliffs.  4 new tests cover normal/EOF/over-
      limit-resync/at-the-boundary.
- [x] **CWE-798 documentary note for SALT constants** in `soft.rs`
      and `usb.rs` — explain that SALT is a public domain-separation
      tag, not a secret.  Recorded in `docs/cwe-top25-audit.md` §CWE-798.
- [x] **CWE-269 documentary audit** on the ns-helper privilege
      chain.  `docs/cwe-top25-audit.md` §CWE-269 walks cap-drop /
      NNP / seccomp / fork / setuid in order with the failure-mode
      analysis.
- [x] **CWE-770 FPE cache eviction policy.**  `mapping/fpe.rs::Cache`
      now bounds the cache to `CACHE_MAX_ENTRIES = 32` entries with a
      FIFO eviction order (equivalent to LRU for our access pattern:
      each table is used heavily during its rotation, never again).
      Three new tests: per-cache eviction at limit, global cache stays
      within bound across 2× insertions, idempotent re-insert.

---

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
