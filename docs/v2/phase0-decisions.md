# Phase 0 — operator decision recommendations

Five operator decisions were filed during phase 0 design work.
After the research rounds in `obfuscation-landscape.md` and
`phase0-research-notes.md`, this document gives my recommendations
on each, ordered by impact.

**Each section: options recap, what the research closed, my
recommendation, why, what I'd want to be wrong about.**

The operator makes the final call.  These are starting positions,
not commitments.

---

## Decision 1 — branch vs subtree for v2 source

**Options:**
- `branch`: develop v2 on a separate branch (`v2-main`); v1 stays
  on `main` / `magical-turing`.
- `subtree`: v2 lives in `crates/v2-*` (or `crates/babbleon-core/`
  etc.) alongside v1 in the same workspace.

**What the research closed:**
- v2's structural-scrambling design is fundamentally a different
  architecture (preprocessor pipeline + multiple new crates), but
  the threat model and many primitives carry forward (HKDF,
  zeroize, tier model, tripwires, response policy).
- Existing Python obfuscators (PyArmor, Pyminifier) ship their own
  source tree; no convention to copy.
- v1's identifier scramble is the reference implementation that
  v2's layer 1 has to match behaviour-wise.

**Recommendation: SUBTREE.**

**Why:**

1. **Differential testing across versions.**  Phase 1's first
   deliverable is "port identifier scramble + tripwires +
   response policy from v1, applying the v2 security baseline and
   naming conventions."  With both versions in one workspace, we
   can write tests that assert v2 produces the same scrambled
   name as v1 for the same `(host_secret, epoch, tool)` triple.
   On a branch, this requires cross-branch checkouts and gets
   messy fast.

2. **Single CI matrix.**  Workspace-level `cargo test` runs both;
   one set of GitHub Actions config; one set of cargo-deny rules;
   one CODEOWNERS.

3. **Incremental migration.**  Operators of v1 can build v2 in
   parallel without checking out a different branch.  v1's tools
   (`rotation-benchmark`, `tokenizer-benchmark`, `scrambler`)
   can target either or both implementations during transition.

4. **v2's structural-scrambling is sufficiently different from
   v1 that there is no risk of accidentally porting v1
   anti-patterns into v2.**  The crate names (`babbleon-core`,
   `babbleon-preprocessor`, `babbleon-launch-untrusted`,
   `babbleon-mapping-worker`) are intentionally disjoint from
   v1's (`babbleon`, `babbleon-cli`, `babbleon-ns-helper`).
   Wrong-crate edits are visible.

**What I'd want to be wrong about:**

If the v1 codebase becomes a magnet for "just fix it here too"
v2 work that should be on v2 crates, the subtree gets messy.
Mitigation: CODEOWNERS with `*v2*` and `*-core/` paths owned by
v2 only; explicit `[v1]` / `[v2]` commit-message prefixes.

If v2's eventual design forks so heavily from v1 that the workspace
churn becomes constant, a late-stage move to a branch is still
possible.

---

## Decision 2 — file extension `.py` vs `.babbleon` for scrambled source

**Options:**
- `.py`: scrambled file keeps Python extension; routing via
  shebang + importlib hooks.
- `.babbleon`: explicit extension; tools that hardcode `.py` are
  broken; clearer to operators.

**What the research closed:**
- Python's PEP 451 import-hook machinery cleanly handles either
  extension by registering a `MetaPathFinder`.
- The shebang mechanism handles top-level invocation regardless
  of extension as long as the file is executable.
- **Module imports do NOT consult shebangs**; they consult the
  importlib machinery.  Both options need a finder.
- PEP 657 column offsets apply to whatever the interpreter
  parses, not what's on disk — so error positions in either
  extension are equally well-served by `babbleon unscramble`.

**Recommendation: `.py` (keep the extension).**

**Why:**

1. **Maximum compatibility with existing tooling.**  pytest,
   setuptools, pyproject.toml entry points, package discovery,
   `find_packages`, MANIFEST.in patterns, every CI matcher I
   know of — all expect `.py`.  Switching to `.babbleon` breaks
   them silently.

2. **The shebang + importlib finder approach is sufficient for
   routing.**  Top-level scripts route via shebang;
   module imports route via the finder.  Both work with `.py`.

3. **Operators who deploy via virtualenvs, conda envs, pyenv,
   uv, rye, etc.** all expect `.py`.  An explicit extension
   change would require coordination with every tool.

4. **Layer 3 (whitespace-as-words) makes the on-disk content
   visibly garbage anyway.**  Any operator running `cat file.py`
   on a scrambled file already sees the answer — "this is
   Babbleon scrambled."  The extension doesn't add information
   beyond what the content already exposes.

5. **The trade-off "explicit signalling vs compatibility"
   resolves toward compatibility** because Babbleon's value is
   in being silently effective, not in announcing its presence.

**What I'd want to be wrong about:**

If a class of tools assumes `.py` content is parseable Python and
crashes hard (rather than gracefully failing) on scrambled
content, the user experience suffers.  Mitigation: ship a
`.babbleonignore` file pattern (analogous to `.gitignore`) so
known-incompatible tools can skip scrambled files; document the
top offenders in `docs/operator/known-incompatibilities.md`.

If operators want a clear visual signal for which files are
scrambled, a `.babbleon.py` double-extension is a compromise
(routes to Python by default but explicit about the layering).

---

## Decision 3 — preprocessor: standalone binary or library

**Options:**
- `standalone`: separate executable; spawned per invocation; tight
  seccomp profile.
- `library`: linked into `babbleon-run` / `babbleon-python` shim;
  no per-call exec cost.

**What the research closed:**
- v1 rotation-benchmark measured ~0.4 ms per shell-wrapper render;
  preprocessor work is more expensive but same order of magnitude
  per file (~5-20 ms estimated).
- PEP 451 import-hook approach can call out to either a binary
  (via subprocess) or a linked library (via Python C extension).
- Layer 5 (junk decoys at ~70% noise) increases preprocessor
  runtime ~3x — relevant to the per-invocation cost calculation.

**Recommendation: STANDALONE binary for v2.0.**

**Why:**

1. **Security boundary > performance for v2.**  The preprocessor
   holds the per-epoch unscramble tables in memory.  An attacker
   reading the linked-in library's memory recovers the tables
   instantly.  A standalone process has its own address space,
   its own seccomp profile, and can apply much tighter syscall
   restrictions than the Python interpreter ever could (Python
   needs `read`/`write`/`stat`/`mmap`/`munmap`/`mprotect`/`brk`/
   `clone`/`futex`/... — the preprocessor needs none of `clone`
   or `futex`).

2. **Easier seccomp profile.**  One binary, one profile, asserted
   in tests.  A linked library inherits the host binary's
   profile; you can't tighten Python's seccomp because Python
   needs everything.

3. **Process boundary = leak boundary.**  If the preprocessor
   crashes or leaks, the parent doesn't go with it.

4. **Per-invocation exec cost is ~5 ms** (Linux fork+exec is fast
   on modern kernels with prefork-amortised binaries).  For
   typical workflows (running a script, importing a small module
   tree), this is negligible.

5. **Easier to swap implementations.**  v2.0 ships a Rust binary.
   v2.1 could ship a wasm-runtime version, or a Lua scripting
   wrapper around a C core, without touching the calling
   convention.

**What I'd want to be wrong about:**

For workflows that invoke 10k small scripts per second (CI test
suites, pre-commit hooks running per-file linters), 5 ms × 10k =
50 seconds of overhead per CI run.  This is real cost.

**Mitigation:** v2.1 ships an *optional* library binding for the
high-frequency case; the security-conscious default remains the
standalone binary.  Operators on big CI runs opt in to the
library mode after evaluating their threat model.

If the standalone exec cost turns out to be 50 ms (not 5),
recalculate.  Benchmark on phase-3 prototype.

---

## Decision 4 — v1 hardening branch

**Options:**
- `stay on magical-turing`: continuity; parallel session work
  already there.
- `rename to v1-maintenance`: signals "this is v1 maintenance,
  not active feature dev"; main becomes v2.

**What the research closed:**
- Nothing in the research directly drives this decision.  It's a
  project-topology / convention question.

**Recommendation: RENAME to `v1-maintenance`.**

**Why:**

1. **Topology clarity.**  Any future maintainer / contributor /
   fork seeing `main` + `v1-maintenance` + (eventually) `v2-main`
   immediately understands the project state.  `magical-turing`
   conveys nothing.

2. **It's free.**  Branch renames are cheap; refs update; all
   commit history preserves.  No PRs are blocked by the rename.

3. **Signals intent to downstream consumers.**  If v1 ever ships
   publicly (even as "the v1 reference implementation"), the
   branch name clarifies its lifecycle status.

4. **`magical-turing` was a session label, not a project
   convention.**  It made sense in context but doesn't deserve to
   become the permanent home of v1 maintenance.

**Implementation:**
```sh
git branch -m magical-turing v1-maintenance
git push origin v1-maintenance
git push origin --delete claude/magical-turing-mele8c  # or keep as redirect
```

(In practice this needs Anthropic-side or operator-side approval
because the session-naming convention is upstream.  If renaming
the existing branch is blocked, the recommendation is "create
`v1-maintenance` from the current `magical-turing` tip and
deprecate `magical-turing` for new commits.")

**What I'd want to be wrong about:**

If `magical-turing` is hard-coded into Anthropic's session
machinery in a way I don't see, the rename creates friction.
Operator can confirm or correct.

---

## Decision 5 — TEE direction (v2.0 enterprise/cloud vs developer laptop)

**Options:**
- `developer-laptops`: v2.0 targets individual developer machines;
  TEE not assumed.
- `enterprise-cloud`: v2.0 targets server / cloud deployments;
  TEE features included.
- `both`: dual track.

**What the research closed:**
- Confidential VMs (TDX, SEV-SNP, Nitro Enclaves) are
  production-shipped across AWS / Azure / GCP / VMware as of 2025.
- **Consumer laptops have neither TDX nor SEV-SNP.**  TDX requires
  Xeon (server-class); SEV-SNP requires EPYC (server-class).
- v1's deployment target was the developer laptop / dev VM; the
  threat model (compromised npm post-install, browser RCE chain,
  curl-pipe-bash payload) is overwhelmingly developer-side.

**Recommendation: v2.0 targets DEVELOPER LAPTOPS + small-business
servers.  TEE is v3.**

**Why:**

1. **v1's stated threat model is developer-side.**  Walking it
   back to "actually we mean enterprise/cloud" abandons the
   audience v1 was designed for.

2. **TEE on consumer hardware is not available.**  Designing for
   TEE in v2.0 means v2.0 is impossible to use on the target
   hardware.  Operators would have to deploy to a confidential
   VM in the cloud just to evaluate Babbleon — that's wrong way
   round.

3. **v2's structural scrambling delivers measurable value
   *without* TEE.**  Layers 2-5 don't require hardware.  Shipping
   those first lets us validate the design before adding hardware
   dependencies.

4. **Enterprise/cloud customers benefit from v2.0 *and* will
   want TEE on top.**  Order them: v2.0 ships the obfuscation
   layers, v3 adds TEE-protected mapping + confidential-VM
   trusted tier.  Enterprise customers either run v2.0 in
   confidential VMs at the deployment layer (compose with v2's
   scrambling) or wait for v3 for tighter integration.

5. **The cost of dropping TEE from v2.0 is small (TEE is purely
   additive); the cost of adding it is large (operational
   complexity, hardware requirements, attestation flows).**

**What I'd want to be wrong about:**

If the operator's actual deployment target is enterprise/cloud and
the developer-laptop framing is legacy, v3-first sequencing is
wrong.  Confirming the deployment target with the operator is
prerequisite to phase-1 work.

If a confidential-VM offering for developer laptops emerges
(e.g. via firmware updates to consumer CPUs, or hardware
virtualisation extensions to existing laptops), revisit.  Apple
M-series secure enclave is the closest analog today and is in
laptops — could revisit specifically for macOS in v3.

---

## Summary table — five recommendations

| # | Decision | Recommendation |
|---|---|---|
| 1 | Branch vs subtree | **Subtree** (`crates/v2-*` in main workspace) |
| 2 | File extension | **`.py` keep** (shebang + importlib finder handle routing) |
| 3 | Preprocessor topology | **Standalone binary** (security boundary > performance) |
| 4 | v1 hardening branch | **Rename to `v1-maintenance`** (topology clarity) |
| 5 | TEE direction | **Developer laptops + small-business in v2.0; TEE in v3** |

---

## What needs to happen after the operator confirms

Once the operator confirms (or corrects) these decisions:

1. **Phase 1 can start.**  All five answer questions that block
   phase 1 implementation:
   - #1 chooses where to put the new code.
   - #2 chooses the file extension v2 emits.
   - #3 chooses what binary topology phase 2's `babbleon-launch-untrusted`
     spawns.
   - #4 chooses the branch v1 maintenance lives on.
   - #5 chooses what phase 6 (release engineering) includes.

2. **Three more phase-0 documents land:**
   - `docs/v2/threat-model.md` — STRIDE + ATT&CK + D3FEND +
     800-190 §4.4/§4.5 + 800-207 seven-tenet map.
   - `docs/v2/security-baseline.md` — designed-in-from-day-one
     checklist.
   - `docs/v2/attack-mapping.md` — full ATT&CK + D3FEND
     traceability matrix.

3. **Implementation begins.**  Phase 1 (core crate skeleton) is
   ~2-3 days of focused work; phase 2 (launcher) is ~1 day; phase
   3 (structural scrambling, the heart) is ~2-3 weeks for the
   first prototype.

---

## Open question I'd raise with the operator

**Where does Babbleon SHIP from?**  We've been assuming a GitHub-
hosted source release.  But Babbleon's threat model includes
"compromised npm post-install" — implying the operator is aware
of supply-chain attacks on their own dependencies.  Should
Babbleon's release path satisfy SLSA L3 (filed as v2 phase 6) or
something stronger (e.g. cosign-signed releases distributed via a
TUF root the operator pins)?

This affects phase 6 scope and shouldn't be deferred to phase 6
to decide.
