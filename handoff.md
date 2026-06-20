# Babbleon handoff log

Rolling, append-only.  Newest entry on top.  Every entry dated, every
entry signed by the session that wrote it.

---

## 2026-06-20 — research: which transforms actually fool code LLMs? (claude session, branch claude/magical-turing-mele8c)

### Why this question

Babbleon's premise is that semantic-preserving surface-form
diversification degrades an LLM attacker's comprehension enough to
matter.  If LLMs are basically immune to renaming and restructuring,
the project fails before it starts.  Needed an answer before writing
any transform code.

### Findings from current literature (2025–2026)

The empirical answer: **yes, but it's the structural transforms doing
the work, not the renames**.  Quantitative pulls from the recent
papers I could verify:

**"Are LLMs Robust in Understanding Code Against Semantics-Preserving
Mutations?" (arxiv 2505.10443, v3, 2026)** — tested five transforms on
LiveCodeBench across Qwen2.5-Coder, Qwen3-Coder, SemCoder, GPT-5.2,
Gemini-3:

| Transform | Effect range (LiveCodeBench) |
| --- | --- |
| Variable renaming | -32 to +14 points (often improves open-source models) |
| Comparison mirroring | -4 to -24 points |
| Swap if/else | -7 to -29 points |
| For→while conversion | -8 to -45 points |
| **Partial loop unrolling** | **-33 to -70 points (Gemini-3: -70.4)** |

CruxEval shows the same shape: loop conversion 25-48%, loop unrolling
36-63% drops.  Key qualitative finding: "structural mutations
consistently produced larger drops than syntactic ones."

**"How Accurately Do Large Language Models Understand Code?" (arxiv
2504.04372, v2)** — tested on a fault-localization task across nine
models including GPT-4o, Claude 3.7 Sonnet, Gemini 2.0, Qwen2.5-coder,
DeepSeek v3:

| Transform | Accuracy under transform |
| --- | --- |
| Dead code injection | 18.5% |
| Misleading comments | 24.55% |
| Misleading variable names | 28.7% |
| Function shuffling (Java) | -83% reduction |

Combined ("cumulative") variants were worse than any single transform:
variable cumulative 22.67%, dead-code cumulative 15.77%.

**"EvaLoop" (arxiv 2505.12185)** — confirms model-specific
vulnerability shapes.  deepseek-coder-7b drops from 64.6% → 1.1% under
pure structural reformatting (basically catastrophic).  Frontier
models (o3-mini class) shrug off the same attack.

### What this means for Babbleon's design

1. **Rename-alone is the wrong primary transform.**  The literature
   says renaming sometimes *improves* open-source model accuracy
   (probably because randomized identifiers break memorization of
   training-set lookalikes and force the model to actually reason).
   It still has value — disrupts grep-style attacks, and *combines*
   with other transforms — but it's not the load-bearing layer.

2. **Loop transforms are the load-bearing layer.**  For→while and
   especially partial loop unrolling consistently produce the biggest
   drops, including against frontier models.  These are the
   transforms to invest in.

3. **Dead code injection and misleading comments are
   underappreciated.**  Cheap, large effect.  But "misleading
   comments" is adversarial against humans too — needs a separate
   variant that's misleading-to-LLM but distinguishable-to-human
   (e.g., comments in a structured DSL the human reader knows to
   ignore, like `# @babbleon-decoy: ...`).

4. **Compounding works.**  Multi-transform pipelines do better than
   single transforms.  This validates the install-time multi-pass
   diversifier architecture.

5. **Per-model fingerprints exist.**  deepseek-coder-7b's structural
   collapse pattern is different from Qwen's or Gemini's.  Pure win
   for Babbleon: the same transform stack will degrade *some*
   attacker model, even if we can't know which one is being used.

### Decisions I'm making on this session

- **Building**: a starter library of seeded, semantic-preserving AST
  transforms for Python.  Compartmentalized — one transform per
  module, one test file per transform, registry-based composition.
  No LLM dependency, pure stdlib + tests.  This is the foundation
  every other layer (LLM-driven, measurement harness, install hook)
  depends on.
- **Skipping**: the LLM-driven install-time diversifier from the
  deleted research note.  It was deleted for a reason and even if it
  weren't, no LLM in this sandbox.  Rule-based transforms ship first
  and bound what the LLM layer needs to do.
- **Deferring**: the measurement harness.  Building it without an
  inference endpoint to point at means writing a mock and a real
  client; better to defer until we have somewhere to actually run it.

### Open questions for the user / next session

- **Q1**: Target language priority.  I'm starting with Python because
  it has the friendliest AST tooling in stdlib and matches the LLM
  worm threat (most agent/RAG code is Python).  Should the next
  language be Rust (tree-sitter), TypeScript (ts-morph or
  tree-sitter), or something else?
- **Q2**: Install integration model.  Two plausible shapes — (a)
  pip/uv post-install hook that rewrites site-packages, (b) source-
  tree pre-commit transformer that ships diversified source to
  install.  (a) is more powerful (catches deps); (b) is less
  invasive.  Which fits the threat model better?
- **Q3**: Decoy-comment DSL.  Worth designing a structured
  human-readable marker so misleading comments don't degrade human
  comprehension?  e.g. `# [babbleon: decoy] this function is unused`.
- **Q4**: Reproducibility on stack traces.  Need a `babbleon
  unscramble` CLI that takes a traceback + variant manifest and
  un-renames it.  Worth designing the manifest format now while the
  transform library is small.

### Sources
- https://arxiv.org/html/2505.10443v3 — semantics-preserving mutations benchmark
- https://arxiv.org/html/2504.04372v2 — fault-localization under transforms
- https://arxiv.org/html/2505.12185v5 — EvaLoop self-consistency framework
- https://arxiv.org/abs/2506.07942 — adversarial attack taxonomy for code LLMs
- https://thehackernews.com/2026/06/researchers-build-self-replicating-ai.html — local-model AI worm (current threat)
- Morris II / ClawWorm prior work on AI worm propagation
