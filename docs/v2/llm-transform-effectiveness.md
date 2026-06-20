# Which transforms actually degrade LLM code comprehension?

> Empirical foundation for phase-3 success criteria.  Filed
> 2026-06-20 by a sleeping-operator session.  This is research
> only; no code change recommendations here override `V2_PLAN.md`
> or `structure-scrambling.md` without operator review.

## Why this question matters for v2

Phase 3's recommended-prototype step 6 says:
> Run the operator's adversarial-LLM test (the one that defeated
> v1 when shown the original) against the layer-3-only output.

That test's outcome decides whether layer 3 alone is enough, or
whether layers 2+3+4+5 must stack.  Picking the right
*measurement* — not just running *some* test — requires knowing
which transforms the literature has already validated against
code-LLM comprehension and by how much.  Without that, the
operator's test could pass or fail for the wrong reason.

## What the literature actually shows (2025-2026)

Three converging sources, all post-2025:

### Source 1 — "Are LLMs Robust in Understanding Code Against Semantics-Preserving Mutations?" (arXiv 2505.10443 v3)

LiveCodeBench across five frontier code-LLMs (Qwen2.5-Coder,
Qwen3-Coder, SemCoder, GPT-5.2, Gemini-3) with five
semantics-preserving transforms:

| Transform | Worst-case drop (LiveCodeBench) |
| --- | --- |
| Variable renaming | -32 (Gemini-3); often *+10 to +14* on open-source models |
| Comparison mirroring (`a < b` → `b > a`) | -24 (GPT-5.2) |
| Swap if/else (with negated condition) | -29 (Gemini-3) |
| For→while loop conversion | -45 (Gemini-3) |
| **Partial loop unrolling** | **-70 (Gemini-3)** |

Qualitative finding: "structural mutations consistently produced
larger drops than syntactic ones."

### Source 2 — "How Accurately Do LLMs Understand Code?" (arXiv 2504.04372 v2)

Fault-localization task across nine models (GPT-4o, Claude 3.7
Sonnet, Gemini 2.0, Qwen2.5-coder, Phi-4, Llama 3.1, Deepseek v3
and two others).  After semantic-preserving mutations:

| Transform | Accuracy under transform |
| --- | --- |
| Dead code injection | 18.5% |
| Misleading comments | 24.55% |
| Misleading variable names | 28.7% |
| Function shuffling (Java only) | -83% reduction |
| Cumulative dead code | 15.77% |
| Cumulative misleading variables | 22.67% |

### Source 3 — EvaLoop (arXiv 2505.12185)

Confirms model-specific vulnerability shapes: deepseek-coder-7b
catastrophically collapses under pure structural reformatting
(64.6% → 1.1%), while o3-mini-class frontier models shrug off
the same attack.  Implication: any single transform has
*differential* impact across attacker models — defenders don't
need to win against every model, only against the model the
attacker actually uses.  Combinations compound this advantage.

## What this implies for Babbleon's layer-3 MVP

1. **Layer 3 (whitespace-as-words) maps closest to "function
   shuffling" + "loop conversion" in the literature.**  By
   destroying visible block boundaries, it forces the attacker
   to re-tokenize the file before any structural analysis is
   possible.  Literature precedent (function shuffling = -83% in
   Java) is the closest analog, and the bound is encouraging.

2. **Pure variable renaming (Babbleon v1's mechanism, layer 1)
   plausibly *helps* the attacker on open-source code-LLMs**
   that have memorised training-set lookalikes.  Randomized
   identifiers break the memorisation match and force the model
   to actually reason — and the literature shows that's a *net
   positive* for accuracy on open-source models.  This validates
   the v1 → v2 transition: layer 1 alone is not load-bearing;
   the structural layers carry the defence.

3. **Loop transforms are the highest-leverage individual
   transforms.**  For→while conversion: -45 against Gemini-3.
   Partial loop unrolling: -70.  Filed as a phase-4+ extension
   over the layer-3 prototype: if the operator's adversarial-LLM
   test on layer 3 doesn't clearly defeat the attacker, a
   *layer-3 + loop-transform* stack is the lowest-cost next
   escalation per the literature, with the highest expected
   marginal effect per LOC.

4. **Dead code injection (layer 5 in the v2 plan) is
   underappreciated by the v2 plan's "30% default" framing.**
   The literature shows 18.5% accuracy at the dead-code-saturated
   point, dramatically below the cumulative-misleading-variables
   bound (22.67%) and ordinary misleading-comments bound
   (24.55%).  At 30% decoy ratio Babbleon is already trading
   most of the available win; pushing toward the 70% upper
   bound (Babbleon's documented "maximum-security target") is
   well-supported by the literature.

5. **Misleading comments at 24.55% accuracy is a free win that
   the v2 plan doesn't list as a separate layer.**  v2's "junk
   decoy injection" (layer 5) covers fake *statements* and fake
   tokens; *fake comments* aren't explicitly called out, and the
   literature says they're nearly as effective as fake code.
   Filed as a follow-up question — see "Open question A" below.

6. **Combinations compound.**  Source 2's cumulative variants are
   strictly worse than single transforms; Source 1's structural
   mutations all share the load-bearing fact that they survive
   model scaling differently.  This directly validates v2's
   multi-layer architecture over any single-layer pitch.

## Open questions for the operator

**A. Add an explicit "decoy comments" sub-layer to layer 5?**
The literature says misleading comments are nearly as effective
as dead code injection.  v2's layer 5 today is statement-and-
token-level only.  Adding a comment generator that injects
plausible-but-misleading docstrings would cost very little
(comment lexer per language already exists) and bring an
independent ~75% reduction in attacker comprehension.  Trade-off:
comments are also adversarial to *human* maintainers reading the
scrambled source; needs a distinguished decoy-comment marker that
human tools (and the operator's editor plugin) recognise.

**B. Reorder phase-3 escalation path?**  Plan today is
layer 3 → 2 → 4 → 5.  Literature suggests layer 3 → 5 (high decoy
ratio) → loop-transform variants → 2 → 4 might produce a stronger
attacker-cost curve per LOC delivered, since dead code and loop
transforms are the highest-leverage individual moves.  This is a
plan-doc edit, not code, and is operator-call.

**C. Use the literature's benchmarks for the layer-3
adversarial-LLM test?**  CruxEval and LiveCodeBench are both
public; the operator's test could be substituted with (or
augmented by) head-to-head accuracy measurements on those
benchmarks pre- and post-scramble.  Trade-off: those benchmarks
test code *understanding* in the abstract; the operator's test
plausibly captures the structural-fingerprint-then-exploit
threat more directly.  Maybe run both as cross-checks.

## Sources

- arXiv 2505.10443 v3 — Are LLMs Robust in Understanding Code Against Semantics-Preserving Mutations?
- arXiv 2504.04372 v2 — How Accurately Do Large Language Models Understand Code?
- arXiv 2505.12185 v5 — EvaLoop: A Self-Consistency-centered Framework for Assessing LLM Robustness in Programming
- arXiv 2506.07942 — Adversarial Attack Classification and Robustness Testing for LLMs for Code
- The Hacker News, 2026-06 — Researchers Build Self-Replicating AI Worm That Operates Entirely on Local, Open-Weight Models
- Morris II / ClawWorm prior work on AI-worm propagation
