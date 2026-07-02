# TODO — Ship Checklist

Concrete work items grouped by milestone.  PLAN.md describes the
v1 *architecture*; `V2_PLAN.md` describes the v2 *redesign*;
`docs/threat-model.md` names what we defend against;
this file is the **shippable list with rationale inline**.

Legend: `[ ]` open · `[x]` done · `[~]` in-progress · `(blocked)` —
blocked on something external · `(v2)` — explicitly tagged as v2
work, not for v1 backport.

When an item is non-trivial, the explanation lives directly under
the checkbox.  Once-deferred items that have landed are marked `[x]`
and kept for audit history; truly historical ones move to commit
messages.

---

## v2 — ground-up redesign

The v1-is-not-the-public-product decision and the phase plan are
in `V2_PLAN.md`.  Doc-only items below are phase 0 (in flight);
code items are phases 1-6.

### Phase 0 — design docs (in flight)

- [x] `V2_PLAN.md` — vision + phase plan
- [x] `docs/v2/structure-scrambling.md` — five-layer mechanism +
      preprocessor design
- [x] `docs/v2/naming-conventions.md` — rename discipline
- [x] `docs/v2/least-privilege.md` — per-syscall capability audit
- [x] `docs/v2/standards-alignment.md` — v1-survey gaps +
      missed-standards inventory (ATT&CK, D3FEND, 800-190,
      800-207, in-toto, TUF, CycloneDX, GUAC, CSAF, SARIF, FIPS,
      CIS, STIG, SAMM, Top 10)
- [x] `docs/v2/threat-model.md` — STRIDE matrix + ATT&CK/D3FEND
      traceability + 800-190 section map + 800-207 zero-trust
      tenet map.  Filed 2026-06-18.  Composes v1's threat-model.md
      (adversary classification) and threat-model-stride.md
      (24-row STRIDE matrix, re-evaluated for v2 with new rows for
      preprocessor / mapping-worker / structural-scramble
      surfaces).  ATT&CK keyed by v17 technique IDs; D3FEND keyed
      by the techniques v2 implements (D3-HCH, D3-MA, D3-PSEP,
      D3-FAPA, D3-DSE, D3-RAPA, D3-OAM); 800-190 §§4.4–4.5 mapped
      subsection-by-subsection; 800-207 mapped tenet-by-tenet.
      The full ATT&CK ⇄ D3FEND traceability matrix is split into
      `attack-mapping.md` (still owed).
- [x] `docs/v2/security-baseline.md` — "designed-in from day one"
      checklist every v2 crate must pass before merge.  15 rules
      (forbid unsafe, deny missing-docs, Zeroizing/SecretBox,
      constant-time compare, HKDF, plain-English names, module-
      doc template, process hardening, SAFETY: comments,
      CAPABILITY: comments, no String secrets, RFC primitives
      only, errors don't leak secrets, &-ref secret args, layered
      tests) + a rule-summary table + a per-crate certification
      procedure.  v2-babbleon-core verified compliant against
      rules 1, 3, 7, 11; pedantic warnings under triage.
- [x] `docs/v2/attack-mapping.md` — full ATT&CK + D3FEND
      traceability matrix referenced from standards-alignment.
      Filed 2026-06-18.  Forward direction: ATT&CK technique →
      status (Defends/Partial/Out-of-scope/N-A) → mechanism →
      D3FEND ID → v2 code surface; sorted by Tactic then ID;
      covers Initial Access through Impact (12 tactics, ~60
      techniques).  Reverse direction: each of the 7 D3FEND
      techniques v2 implements with the ATT&CK IDs it raises
      cost on.  Coverage-statistics table by tactic +
      doc-limitation pointers.  Strongest coverage: Credential
      Access (11 Defends) and Discovery (4 Defends).

### Phase 0 — operator decisions CONFIRMED 2026-06-15

- [x] Branch vs subtree for v2 source — **subtree at `crates/v2-*`**
- [x] File extension for scrambled source — **keep `.py`**
      (shebang + importlib finder handle routing)
- [x] Preprocessor topology — **standalone binary**
      (security boundary > performance)
- [x] v1 hardening branch — **rename to `v1-maintenance`**
      (mechanical rename out-of-band)
- [x] TEE direction — **v2.0 = developer + small-business; TEE in v3**
      (consumer hardware has no TDX/SEV-SNP)

### Phase 0 — additional operator decisions confirmed

- [x] Shipping plan: **GitHub releases with checkable checksums**
      (default), **+ project website mirror** (redundancy), **+
      expected downstream sec-vendor packaging** under PolyForm
      Commercial licenses.

### Phase 0 — open research (not blocking phase 1)

- [x] **Dynamic / language-agnostic keyword extraction** for v2
      layer 2.  DONE: replaced the Python-specific keyword and
      operator scramblers with a fully dynamic identifier
      scrambler (`crates/v2-babbleon-preprocessor/src/
      identifier_scrambler.rs`).  Every whitespace-delimited
      token in the source (keywords, operators, identifiers,
      string literals, punctuation — all of it) is collected,
      assigned per-epoch compound aliases, and replaced.
      Language-specific keyword/operator lists are gone;
      `python_keywords.rs`, `python_operators.rs`,
      `keyword_scrambler.rs`, `operator_scrambler.rs`,
      `keyword_wordlist.rs`, `operator_wordlist.rs` deleted.
      Multi-alias (ALIAS_COUNT=3) defeats frequency analysis:
      each token gets 3 independent compounds cycling across
      occurrences.  Daemon protocol updated: `GetTokenMapping` /
      `TokenMapping` replaces `GetKeywordCompounds` /
      `KeywordCompounds`.  Full round-trip + property tests
      pass.
- [x] **Algorithmic derivation of per-role wordlist pool
      sizes.**  Closed 2026-07-02 by
      `tools/wordlist-role-partitioning/`.  The tool applies a
      Birthday-bound target (`H = 2·log2(events) +
      collision_margin + log2(lifetime)`) for compound_n ≥ 2
      draws and a Uniqueness bound (`log2(events × alias_count ×
      safety)`) for permutation-driven / compound_n = 1 roles,
      then reports per-role pool sizes plus fit-in-wordlist
      verdict.  Under the laptop-default posture the six-role
      table uses 215 387 words (58 % baseline / 97 %
      intersect[3,5]).  Under the paranoid preset the strict
      1e-12 target requires ~20 M words — a real signal that
      phase-4's multi-language pool is a prerequisite for that
      posture.  See `tools/wordlist-role-partitioning/RESULTS.md`
      for the sensitivity table and
      `docs/v2/phase0-research-notes.md` §11 2026-07-02 addendum
      #2 for the cross-reference.

### Phase 1 — v2 core crate (code; awaiting phase-0 decisions)

- [ ] `crates/babbleon-core/` skeleton with v2 naming + security
      baseline applied
- [ ] HKDF (RFC 5869) for domain separation (v1 has this; carry
      forward)
- [ ] `secrecy::SecretBox` for every secret-holding type
- [ ] `#[forbid(unsafe_code)]` at every crate root with `unsafe`
      quarantined to one syscall module per crate
- [ ] Per-syscall `CAPABILITY:` comments per `docs/v2/least-privilege.md`
- [ ] Identifier scramble + tripwires + response policy ported
      from v1 (the v1 implementation is reference; rewrite under
      v2 conventions)

### Phase 2 — v2 launcher + PAM

- [ ] `crates/babbleon-launch-untrusted/` (NOT setuid; file caps:
      cap_sys_admin, cap_setuid, cap_setgid, cap_ipc_lock)
- [ ] PAM module wires through the new launcher
- [ ] Capability-set test that asserts CapEff at each lifecycle
      stage matches the documented `CAPABILITY:` comments

### Phase 3 — structural scrambling

- [x] `crates/v2-babbleon-preprocessor/` — runtime unscrambler
      (`unscrambler.rs`, `tokens_to_source`)
- [x] **Layer 2: dynamic identifier scrambler** — language-agnostic;
      scrambles every whitespace-delimited token; ALIAS_COUNT=3
      multi-alias per token.  See `identifier_scrambler.rs` +
      daemon `state::token_mapping()`.  File header stores token
      list so unscramble re-derives mapping from daemon without
      original source.
- [x] **Layer 3: whitespace-as-words** — `WhitespaceWordlist`,
      `python_tokenizer::tokenize`, `scrambler::scramble`,
      `unscrambler::unscramble_to_tokens`.  Output is one
      continuous wall of compound tokens; no whitespace or
      newlines visible.
- [x] **Layer 4: chunk reorder with position markers** —
      `chunk_reorder.rs`.  Top-level chunks are reordered
      deterministically per epoch; each chunk carries a
      `__bbnpos<N>__` marker the unscrambler reads to restore
      original order.  Defeats "imports first, helpers next,
      main last" structural fingerprinting.  Wired into
      `scramble_lifecycle.rs` (per-file CLI) and
      `corpus_lifecycle.rs` (batch dir).
- [x] **Layer 5: decoy injection** — `decoy_injection.rs`.
      Per-epoch `__bbndecoy<N>__` tokens injected at depth-0
      positions (~25% of original token count).  The unscrambler
      recognizes and strips them by prefix before L4 reorder.
      Wired into the same lifecycle modules as L4.
- [x] Update `CLAUDE.md` and `README.md` to document the v2
      preprocessor pipeline (L2 dynamic identifier scrambler +
      L3 whitespace-as-words + L4 chunk reorder + L5 decoy
      injection, file header format, multi-alias, daemon
      protocol).
- [x] Preprocessor seccomp profile (deny socket / mount / ptrace
      family) — `crates/v2-babbleon/src/seccomp_profile.rs`, 34-syscall
      allowlist, installed after last daemon call pre-computation.
      Corpus-dir gap documented; v2.1 batch-prefetch TODO filed.
- [ ] Adversarial-LLM re-test: did L2+L3+L4+L5 fix the v1
      shape-fingerprint problem? (bench matrix in progress 2026-06-26)
- [x] **Randomize `ALIAS_COUNT` per epoch.**  Landed across the
      2026-06-27 session: commits `9d9af7f` (primitive),
      `21b4cd7` (wire protocol + lifecycle), `405d7fe`
      (end-to-end round-trip test), `d38a370` (bench coverage).
      Both back-compat options from the original task ended up in
      the same commit:  file format bumped to version 2 AND the
      preprocessor's `alias_count_for_epoch(version, epoch)`
      returns the legacy `ALIAS_COUNT=3` for `version < 2` so
      v0/v1 files unscramble cleanly under the new daemon.  The
      wire field is `format_version: u32` (not `alias_count: u8`)
      because the daemon needs both `K` and the virtual-epoch
      stride; deriving both from version keeps the two ends in
      sync without a second wire field.  See `HANDOFF.md`
      2026-06-27 block for the full design + stats.

### Phase 4 — additional obfuscation layers (post-research)

Layers 6-12, filed from `docs/v2/obfuscation-landscape.md`.  Each
composes with the phase-3 five-layer base; they don't replace it.

- [x] **Layer 6 — direction segment reversal (MVP)** —
      `direction_reversal.rs`.  Variable-length char chunks
      (`MIN_CHUNK_CHARS=16 .. MAX_CHUNK_CHARS=48`) reversed per a
      per-epoch xorshift PRNG with `REVERSE_DENOM=2` (fair coin
      per chunk).  Reversal is involutive, so the unscrambler
      side is a literal call to the same `reverse_chunks`
      function with the same epoch — the PRNG reproduces the
      same chunk-size and reverse-decision sequence on both
      passes.  Wired into `scramble_lifecycle.rs` and
      `corpus_lifecycle.rs` between L3 and L12.  Tests: 10 unit
      tests (round-trip, determinism, char-multiset preservation,
      multi-byte UTF-8 safety) + 2 integration tests
      (L6-only round-trip, L6+L12 compose-and-invert).  Marker-
      wordlist variant from the original landscape doc is
      deferred: the deterministic-PRNG variant requires no
      in-stream markers, so the marker-as-target attack surface
      is moot.  An attacker who knows the epoch trivially undoes
      L6 (same threat boundary as L12); protection of the epoch
      itself comes from the daemon never leaving the trusted
      tier.  Display-bidi remains rejected as theatre (collides
      with Trojan Source linters; LLMs see bytes not display).
- [ ] **Layer 7 — source-level control-flow flattening.**
      Composes with layers 2-5: existing unflatteners (D810,
      CaDeCFF) pattern-match against switch-case shapes that
      whitespace-as-words destroys.  Cost: ~20-50% runtime
      overhead per literature.
- [ ] **Layer 8 — opaque predicates + bogus control flow.**
      Always-true / always-false branches; cheap (5-15%
      overhead); LLMs are inconsistent at integer-arithmetic
      reasoning under load, exactly the case opaque predicates
      exploit.
- [ ] **Layer 9 — constant unfolding.**  `port = 22` becomes
      arithmetic over wordlist-scrambled identifiers.  Composes
      with the wordlist scramble naturally.
- [ ] **Layer 10 — path-string obfuscation (narrow scope).**
      Host-path string literals rewritten to consult the
      scrambled-path table at runtime.  Not general string
      obfuscation (that changes program semantics).
- [x] **Layer 12 — tokenizer-hostile noise** —
      `tokenizer_noise.rs`.  Body-bytes-only perturbation: zero-width
      character injection (ZWSP/ZWNJ/ZWJ at U+200B/200C/200D) at
      deterministic per-epoch positions, plus Cyrillic-homoglyph
      substitution for Latin `a c e i o p x y` (U+0430/0441/0435/
      0456/043E/0440/0445/0443) on a ~1/3 PRNG draw.  Strip is
      content-based and idempotent — older pre-L12 files unscramble
      correctly under the new pipeline.  Wired into
      `scramble_lifecycle.rs` (per-file CLI) and `corpus_lifecycle.rs`
      (batch dir) so L12 runs after L3 emits its body and is the
      first inverse step on unscramble.  Confined to the scrambled-
      source representation; interpreter sees clean ASCII.  Cost on
      attacker: real (multi-x BPE token-count inflation in limit
      cases).  Cost on us: zero (clean-source-side).

### Phase 4 — supporting research and measurement

- [ ] Adversarial-LLM measurement on phase-3 prototype against
      the same models that defeated v1 when shown the original.
      Required: cannot stack phase-4 layers on top of phase-3
      until we know phase-3 actually helped.
- [x] Smaller-model superlinear-token-cost hypothesis test —
      **closed 2026-07-02 with a null result** (session 2,
      commit `b97ba64`).  `tokenizer-benchmark --include-smaller`
      compares r50k / p50k against cl100k / o200k on the
      production wordlist.  Smaller-vocab tokenizers do cost
      MORE absolute tokens per compound (~7 % r50k vs o200k),
      but the compound-to-spaced RATIO stays ~1.06× regardless
      of vocab size, so the "compound tax" is not superlinear
      in vocab shrinkage.  See
      `tools/tokenizer-benchmark/RESULTS.md` §"Smaller-model
      tokenizer comparison".  Note: this uses OpenAI's tiktoken
      BPE family; the TODO §575 open-weights hypothesis
      (SentencePiece for Llama/Mistral/Phi) is a separate
      untested question.
- [ ] TEE direction decision: does v2.0 target
      individual-developer deployment (no TEE) or
      enterprise/cloud (TEE available)?  Different priority for
      v3 work.

### Phase 4 — multi-language wordlists

- [ ] **Vendor [HermitDave/FrequencyWords](https://github.com/hermitdave/FrequencyWords)
      multilingual lists** (MIT license, 61 languages from
      OpenSubtitles 2018).  Source identified 2026-06-15.
      Provisional N=100k entries per language; 16 languages →
      ~1.6M total.  Top 16 by language: EN (already shipped),
      ES, FR, DE, JA, ZH-Hans, ZH-Hant, AR, RU, PT-BR, IT, NL,
      PL, TR, HI, KO.  Settle final list per phase 4.
- [ ] Per-epoch language cycling logic in `babbleon-core`.
- [ ] Re-run `tools/tokenizer-benchmark/` on multilingual
      compounds vs spaced English; smaller-model superlinear
      hypothesis.
- [ ] Wordlist-pool allocation table — which N-word subset
      goes to which role (identifier / keyword / whitespace /
      decoy / direction-marker / prompt-injection) per epoch.
      Disjoint subsets prevent cross-class leakage.  Sizes
      provisional: identifier ~370k, decoy ~100k, direction
      marker ~20k, whitespace ~10k, keyword ~5k per language,
      prompt-injection ~0.5k.

### Phase 5 — hardware backends

- [ ] FIDO2 hmac-secret (blocked on YubiKey delivery)
- [ ] TPM2 PCR-sealed (blocked on TPM hardware)
- [ ] TPM authorized-policy for post-kernel-update re-seal

### Phase 6 — release engineering

- [ ] SLSA L3 reusable workflow
- [ ] CycloneDX 1.6 SBOM
- [ ] cosign signing (sigstore) + in-toto attestations
- [ ] AppArmor + SELinux profile templates (v1 has these; carry
      forward)
- [ ] CIS + STIG deployment docs
- [ ] CSAF 2.0 advisory pipeline
- [ ] SARIF emission from CodeQL/Semgrep (v1 has CodeQL; verify
      SARIF upload)
- [ ] Adopt CycloneDX as the only SBOM format (v1 left this
      undecided)

### Missed-standards remediation (v2-tagged)

- [ ] ATT&CK technique mapping in threat model (T1059, T1057,
      T1083, T1552.*, T1574, T1518, T1003, ...)
- [ ] D3FEND technique mapping (D3-HCH, D3-MA, D3-PSEP, D3-FAPA,
      D3-DSE, ...)
- [ ] NIST SP 800-190 §4.4 section-by-section threat-model map
- [ ] NIST SP 800-207 zero-trust tenet map
- [ ] in-toto + TUF substrate adopted (already implied by sigstore
      toolchain)
- [ ] CycloneDX 1.6 chosen as the SBOM format (decision recorded
      in `docs/v2/standards-alignment.md`)
- [ ] GUAC-ingestible SBOM publication
- [ ] CSAF 2.0 JSON output for advisories
- [ ] SARIF upload from SAST jobs
- [ ] FIPS 140-3 deferred to v3 (decision recorded)
- [ ] CIS deployment doc
- [ ] DISA STIG deployment doc (lower priority than CIS)
- [ ] OWASP Top 10 (2021) documentary audit (most items n/a; sweep
      anyway)

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
- [~] **Wordlist post-filter by tokenization density.**  v2 mapping
      change: pick wordlist entries that score in the mid-tail of
      cl100k/o200k token density.  Analysis tool +
      density measurement landed 2026-07-02 in
      `tools/wordlist-density-analysis/` (see `RESULTS.md` there for
      the full filter matrix).  Distribution is peaked (73-76% of
      the corpus at 2-3 tokens), so absolute-token cutoffs are the
      natural knob.  Baseline recommendations for the wiring change:
      cl100k [3, 5] (244 804 kept, 66.2%) or cl100k [3, 4] (225 886
      kept, 61.1%).  Blocked on the adversarial-LLM re-test
      producing a baseline before we commit to one filter over the
      other or over the current 369 652-entry baseline.

## HTML scrambler

- [x] `tools/scrambler/index.html` — standalone harness (417 lines, complete)
- [x] **`tools/scrambler/example-puzzles/`** — five Python puzzles
      (difficulty 1–4) covering FizzBuzz, running max, anagram
      grouping, balanced-parens stack, and merge-intervals.  Each
      file has a single `# {{INSERT}}` marker and a built-in
      `assert ... print("ok")` test.  `solutions.txt` carries the
      reference completions (do NOT show to the LLM under test).
      Each puzzle verified solvable against its reference solution.
      Filed follow-ups: C + Rust variants, type-juggling /
      async / exception puzzles, automated scoring harness.

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

- [x] **Operator scrambling.**  DONE — subsumed by the dynamic
      identifier scrambler (L2).  Every operator (`(`, `)`, `==`,
      `:`, `**`, `-`, etc.) is a whitespace-delimited word token and
      gets its own per-epoch compound alias.  No separate operator
      list or `operator_scrambler.rs` needed.
- [x] **Whitespace-as-words.**  DONE — `WhitespaceWordlist` +
      `scrambler::scramble` / `unscrambler::unscramble_to_tokens`.
      All spaces, tabs, and newlines are replaced by per-epoch
      compound tokens; output is one continuous wall of words.
- [x] **Multi-output scramble (multi-alias, ALIAS_COUNT=3).**  DONE —
      each unique token gets 3 independent HKDF-derived compound
      aliases (virtual epochs `epoch*3+0 .. epoch*3+2`); the
      scrambler cycles through them per-occurrence so frequency
      analysis cannot reconstruct the token set from compound
      frequencies alone.
- [x] **Code-order scrambling with execution markers.**  DONE — see
      `chunk_reorder.rs`.  Top-level chunks are reordered
      deterministically per epoch with `__bbnpos<N>__` markers.
- [x] **Junk-line / decoy-token injection.**  DONE — see
      `decoy_injection.rs`.  Per-epoch `__bbndecoy<N>__` tokens
      injected at ~25% of original token count; stripped by prefix
      at unscramble.
- [ ] **Multi-language wordlists.**  Cycle through wordlists from
      multiple natural languages (EN, ES, FR, DE, JA, ZH, AR, ...) per
      rotation, or mixed within a single rotation.  Hypothesis: LLM
      attention over a one-language scramble has a single attention
      head pattern; multi-language scramble fragments that pattern.
      Likely small effect because models reason in semantic space, not
      surface tokens — but cheap and the gain is non-zero.

The remaining research item (multi-language wordlists) is not for v1.
It reshapes the threat model substantially and deserves a research
write-up of its own (adversarial test against frontier models before
committing).  Filed here so the line of thinking is recorded.

## Security practices to land (industry-standard, currently missing)

Triaged from a self-review against general secure-software practice.
"High leverage" = low effort, big credibility / safety win; "should-have"
= worth doing before any public release.

### High leverage — land first

- [x] **`SECURITY.md` / RFC 9116 `security.txt`** at repo root.
      Shipped in commit `dc9e25d` (pre-session).
- [x] **Memory zeroization of secrets via `zeroize`.**  Shipped in
      commit `8c34403` (pre-session) — `host_secret`, KEK material,
      and vault payload bytes now sit in `Zeroizing<Vec<u8>>` and
      wipe on drop.
- [x] **Constant-time comparison for secret-derived bytes** via
      `subtle::ConstantTimeEq`.  `crates/babbleon/src/crypto.rs` exposes
      `ct_eq(&[u8], &[u8]) -> bool`; `MappingTable::is_honey` now uses
      it (full traversal, no early-exit) so neither the matching index
      nor the no-match outcome is leakable by timing.  Pattern set up
      for FIDO2 / Ed25519 sites where comparison against attacker input
      is load-bearing.
- [x] **Daemon hardening: refuse core dumps, refuse swap.**  Shipped
      in commit `a8351bd` (pre-session).
      `crates/babbleon/src/process_hardening.rs` calls
      `prctl(PR_SET_DUMPABLE, 0)`, `setrlimit(RLIMIT_CORE, 0)`, and
      `mlockall(MCL_CURRENT | MCL_FUTURE)` at CLI start; failures
      degrade gracefully (warn + continue) so containers without
      CAP_IPC_LOCK still run.
- [x] **`SAFETY:` comments on every `unsafe` block.**  Shipped in
      commit `9348ae3` (pre-session).

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
- [~] **`cargo-vet` for transitive-dep audits** alongside the existing
      `cargo-deny` / `cargo-audit`.  Bootstrap landed in
      `supply-chain/config.toml` with import URLs for bytecode-alliance,
      embark-studios, google, mozilla, and zcash audit collections;
      first-party workspace crates marked `audit-as-crates-io = false`
      so they're reviewed via CODEOWNERS instead.  Empty `audits.toml`
      + `exemptions.toml`.  `.github/workflows/ci.yml` `vet` job runs
      `cargo vet --locked` in `continue-on-error` mode and uploads a
      `cargo-vet-report` artifact on failure.  Flip continue-on-error
      off once an operator runs `cargo vet regenerate exemptions` to
      backfill the initial exemption set.
- [x] **Reproducible-build verification CI job.**
      `.github/workflows/ci.yml` `reproducible` job builds the
      release binaries twice from the same checkout on the same
      runner, `cargo clean`s between, and compares SHA-256s of the
      `babbleon` and `babbleon-ns-helper` output.  Cross-runner
      verification is the stronger guarantee — filed as a stretch
      follow-up once the same-runner version stays green.

### Testing

- [x] **`cargo-fuzz` on three surfaces** — scaffolding shipped in
      `fuzz/`:
      - `honey_fifo_line` — drives `HoneyFifoReader::run` end-to-end
        (the parser is private; reaching it through the public path
        is the closest surface)
      - `fpe_roundtrip` — asserts `decrypt(encrypt(x)) == x` over
        arbitrary seed/epoch/n/x
      - `wrapper_render` — drives `write_wrapper` with arbitrary
        decoy banner inputs; sanity-checks the rendered shell-script
        printf-line for runaway quotes
      Targets are listed in `fuzz/README.md` along with the run
      commands; CI integration filed below.
- [x] **Weekly fuzz CI workflow.**  `.github/workflows/fuzz.yml`
      runs each cargo-fuzz target for 5 min on Sunday 02:00 UTC (plus
      manual `workflow_dispatch`).  Crashes upload as
      `fuzz-artifacts-<target>` 30-day artifacts on failure.
- [x] **`proptest` / `quickcheck` on mapping bijection.**
      `crates/babbleon/tests/mapping_properties.rs` covers six
      properties at 16 cases each (each `build_table` cold-builds the
      370k-entry permutation, so case-count is wall-clock-bound):
      bijection (no collisions, scramble∘reveal = id), honey
      disjointness, determinism, secret separation, FPE round-trip,
      and rotation moves every entry.  Full property suite runs in
      ~56 s.
- [x] **`miri` runs in CI** to catch UB in unsafe-libc blocks.
      `.github/workflows/ci.yml` `miri` job (nightly + `-Zmiri-disable-
      isolation`) runs the mapping/crypto/audit/vault::attempts unit
      tests under Miri.  Integration tests that shell out, mount NS,
      or call mkfifo for real are intentionally skipped.

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
- [x] **CodeQL or Semgrep SAST** in CI.  `.github/workflows/codeql.yml`
      runs CodeQL with the `security-extended` query suite over GH
      Actions workflows (on push/PR to main + weekly Wed cron).
      CodeQL Rust support is marked beta upstream — revisit adding
      the `rust` matrix entry when it ships to stable.  C support
      (the PAM shim) is filed for once libpam-dev is in the runner
      image consistently.
- [x] **STRIDE-formatted threat model.**  `docs/threat-model-stride.md`
      — 24-row STRIDE table covering Spoofing / Tampering /
      Repudiation / Information-Disclosure / Denial-of-Service /
      Elevation-of-Privilege threats, each with a status + reference
      back to the code surface or doc artifact.  Companion to the
      existing `docs/threat-model.md` (which is structured around
      the AI-attacker classification).
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
- [x] **Backup/restore policy for stale mapping archives.**
      `crates/babbleon/src/backup.rs` now exposes `RestorePolicy`
      (RejectMismatch · RewrapToCurrent · HonorSnapshotUntilNextRotation)
      and `BackupBundle::resolve_against(&current_session, wordlist,
      policy)` which returns a `ResolvedRestore { policy, renames }`
      plan.  Rewrap mode computes the O(N) `(from, to)` rename list;
      honor mode returns an empty plan (daemon activates the
      bundle's mapping for one cycle).  Cross-host restore is refused
      even in rewrap mode.  CLI commands `babbleon backup --out
      <file>` and `babbleon restore --in <file> --policy
      <reject|rewrap|honor-snapshot>` are wired through.  Filesystem-
      side rename execution is a separate follow-up.  4 new tests
      cover the policy logic.

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
