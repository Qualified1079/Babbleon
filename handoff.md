# Handoff / research notes

## 2026-07-08 — [research][built] LLM-worm threat landscape + no-LLM syntactic diversification prototype

**Context.** No `claude.md` or `handoff.md` existed in this repo prior to
this entry (checked full git history — the only prior related work was
`c2000e0`/`3188d0a`, an "LLM install-time semantic diversification"
research track that was added then deleted, presumably superseded or
parked). Picking this back up with fresh research before building.

### Threat landscape (why this matters now)

- **Morris II (2024)** — first published GenAI worm. Self-replicating
  adversarial prompt spreads through RAG-backed email assistants; no
  click required, propagates by getting the LLM to forward/re-inject
  itself. [IBM summary](https://www.ibm.com/think/insights/malicious-ai-worm-targeting-generative-ai),
  [NeuralTrust](https://neuraltrust.ai/blog/self-replicating-malware).
- **CleverHans Lab worm (June 2026)** — qualitatively different and more
  relevant to Babbleon's premise: a self-replicating worm that runs
  entirely on a single-GPU **local, open-weight** model, so it doesn't
  depend on and isn't visible to any API-level safety layer. On a 33-host
  test network it found 31.3 vulnerabilities/host on average, escalated
  on 23.1 hosts, and replicated to 62% of the network in 7 days
  unsupervised. Critically, it does **not** carry pre-written exploits —
  it reasons out exploitation chains (SambaCry, Dirty Pipe,
  PrintNightmare, Drupalgeddon 2, etc.) at runtime from what it observes
  on each target, and it bypassed its own training cutoff by ingesting
  public CVE advisories at attack time.
  [The Hacker News](https://thehackernews.com/2026/06/researchers-build-self-replicating-ai.html),
  [arXiv:2606.03811](https://arxiv.org/html/2606.03811v1),
  [Schneier on Security](https://www.schneier.com/blog/archives/2026/06/ai-worm.html).
- **Defense literature (2026)** for the prompt-injection propagation
  vector is converging on canary tokens / honeypot tool definitions
  (e.g. a fake `reveal_system_prompt` tool — any call to it is
  unambiguous proof of injection) plus instruction-hierarchy and
  output-filtering layers.
  [ITNEXT honeypot writeup](https://itnext.io/catching-ai-red-teamers-in-the-wild-using-reverse-prompt-injection-as-a-honeypot-detection-36e2f3327611),
  [OpenAI defense guide summary](https://lushbinary.com/blog/ai-agent-prompt-injection-defense-production-playbook/).

**Takeaway for Babbleon:** the CleverHans-style worm's core power is that
it *reads a target and reasons about it fresh*. That's exactly the step
Babbleon's premise (confuse the worm) can attack — not by stopping
reconnaissance, but by making what it reads unreliable or non-transferable
across hosts, so per-target reasoning cost stays high and cached/learned
exploit chains don't generalize.

### What got built: `babbleon/diversify.py`

The deleted research track proposed an LLM-driven AST rewriter (needs a
local 32B-class coder model, GPU, 20-30h per fresh install — see deleted
commit `c2000e0` for the full writeup). That's real, but it's a big,
model-dependent build. This is the **no-LLM precursor**: a pure-`ast`,
deterministic, seed-keyed renamer for Python source.

- Renames function-local identifiers (locals, tuple-unpack targets,
  `except ... as e`, walrus targets — including ones that leak out of a
  comprehension into the enclosing function) to `sha256(seed:qualifier:
  name)`-derived pseudonyms.
- Provably excludes anything where renaming could change behavior:
  parameters, `global`/`nonlocal`-declared names, and — importantly —
  any name referenced anywhere inside a nested function/lambda/class
  (closures are skipped entirely rather than risk getting shadow-vs-
  capture wrong). Module-level names, imports, and function/class names
  are never touched, so the public API surface is stable.
- Same seed → byte-identical output (reproducible builds); different
  seed → different identifiers. Two installs of the same repo, two
  different seeds, textually distinct source, identical behavior.
- Tests in `tests/test_diversify.py` (11 cases, all passing) cover
  behavior-preservation via actual execution (not just re-parsing),
  determinism, the closure/global exclusion safety net, tuple unpacking,
  exception aliases, and walrus-in-comprehension scope leakage. Also
  stress-tested by having the tool diversify its own source file and
  confirming the diversified copy still runs and still correctly
  diversifies further code.

Run it: `python3 -m babbleon.diversify path/to/file.py --seed <per-install-seed>`

**What this does and doesn't buy you** (being honest, per the deleted
track's own framing):
- Does: break naive textual/structural fingerprinting and cross-host
  copy-paste of an exploit chain that references specific local variable
  names or that an LLM described in terms of "the variable called `x`".
  Zero GPU cost, safe to run on every build.
- Doesn't: touch control flow, function/class names, or file layout —
  which is most of what a *reasoning* worm (like CleverHans-style) is
  actually keying on when it infers "this is a Flask app with a SQL
  injection at line N". This prototype is a floor, not the ceiling — the
  original LLM-driven track (semantic/control-flow rewrites, equivalent
  stdlib swaps) is still the deeper play and is what actually addresses
  reasoning-based recon rather than pattern-matching recon.

### Open items for manual review (not built — need a decision, not just code)

1. **Canary/honeytoken tripwires.** Well-precedented, cheap, and
   complementary to diversification (diversification raises the worm's
   cost per attempt; canaries turn a failed/successful attempt into a
   detection signal). Not built because it requires attacker-facing
   infrastructure (a listener endpoint for the canary to call home to)
   and a decision on where that lives — that's an infra/ownership call,
   not something to stand up unilaterally.
2. **Reviving the LLM-based track.** The deleted `c2000e0` writeup is
   still solid; nothing here supersedes it. Worth deciding whether it
   comes back as-is, or whether this AST-based renamer becomes its
   "tier 0" (cheap, always-on) with the LLM pass as an optional "tier 1"
   for higher-value control-flow/algorithmic rewrites.
3. **Extending diversify.py beyond identifier renaming**: safe statement
   reordering (independent top-level statements, independent local
   assignments), equivalent-construct swaps (`for`/comprehension,
   `if/else` ordering flips) — all still LLM-free and AST-provable, and a
   natural next increment before reaching for the LLM tier.
4. **Non-Python targets.** Current prototype is Python-only (stdlib
   `ast`); most real fleets are polyglot. A tree-sitter-based version
   would generalize but adds a dependency — worth a call on whether that
   tradeoff is acceptable before investing there.

---
*Tags: #research #llm-worm #diversification #mtd #2026-07-08*
