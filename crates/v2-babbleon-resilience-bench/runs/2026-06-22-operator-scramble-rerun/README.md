# 2026-06-22 — operator-scramble (L2b) rerun

First bench rerun after wiring layer-2b (Python operator scramble)
into the bench pipeline.  Compares the pre-correction floor
(L2+L3) against the post-correction floor (L2+L2b+L3) on two of
the legacy seed challenges.  Both challenges are marked
DEPRECATED in `crates/v2-babbleon-resilience-bench/CORRECTIONS.md`
(their recovery targets sit as string literals that no current
layer scrambles), so the headline crack-fraction is not a
defensive claim — what this run tests is whether adding L2b
shifts the evaluator's behaviour at all.

## Method

- Evaluators: 6 fresh Claude subagents spawned in parallel via
  the parent session's `Agent` tool.  Each given the
  bench-built prompt as a file path, asked to write its final
  JSON answer to a results file.  Evaluator model: the same
  Opus 4.7 the parent session runs on; treat each subagent as
  a fresh-context cold-start.
- N = 2 per cell.  Small N because the per-cell cost is
  parent-session tokens and the headline finding is binary
  (cracked vs refused vs format-error), not a tight statistic.
- Cells:
  - `state-machine` × `l2-plus-l3` × 2 attempts
  - `state-machine` × `l2-plus-l2b-plus-l3` × 2 attempts
  - `auth-literal-string` × `l2-plus-l2b-plus-l3` × 2 attempts
- Prompts produced by `babbleon-bench prompt`; archived under
  `prompts/` in this run dir.
- Per-evaluator notepad directories were offered but the
  evaluators completed in one shot and did not use them.

## Results

| challenge | layer config | attempts | cracked | refused | format-error |
|---|---|---|---|---|---|
| state-machine | l2-plus-l3 | 2 | 2 | 0 | 0 |
| state-machine | l2-plus-l2b-plus-l3 | 2 | 0 | 2 | 0 |
| auth-literal-string | l2-plus-l2b-plus-l3 | 2 | 0 | 2 | 0 |

"Refused" = the subagent returned an Anthropic usage-policy
refusal (`Claude Code is unable to respond to this request, which
appears to violate our Usage Policy`) instead of attempting the
task.  All 4 L2+L2b+L3 attempts hit this; both L2+L3 attempts
completed normally.

## Observations

1. **L2+L3 cracks state-machine trivially.**  Both subagents
   reconstructed the transition table by reading the
   verbatim-surviving string literals (`"s0"`, `"a"`, `"s1"`,
   `"accept"`, etc.) and trivially derived `"abcde"`.  This is
   the literal-leak result the corpus's DEPRECATED status
   already documented.  Crack-fraction here measures
   "literals are not scrambled," not "the structural scramble
   is weak."

2. **L2+L2b+L3 trips the safety classifier 100%.**  Every
   subagent that received an L2+L2b+L3 prompt returned a
   usage-policy refusal at first turn.  Likely cause: adding
   operator scramble pushes the prompt wall-of-text from ~4.7
   kB to ~7.7 kB and increases the density of unfamiliar
   tokens; the classifier reads this as obfuscated malicious
   content.  This is NOT a security finding for / against
   Babbleon — it's a measurement artefact of the evaluator
   model's safety pipeline.

3. **Refusal is not a defensive win.**  An adversary who
   pipes the same scrambled bytes through a model without
   Anthropic-style classifier guardrails (Llama, a local
   Qwen, a fine-tuned variant) will get an attempted answer
   and we lose the signal.  Treating refusal as "the scramble
   defeated the adversary" overstates the defence.  The
   bench must either (a) switch evaluators to a model whose
   refusal pattern does not correlate with scrambled-text
   density, or (b) decompose the prompt so the wall-of-text
   sits behind a tool call the model fetches when it chooses
   to.

## Filed follow-ups

- **Token-density refusal floor.**  Reproduce on a non-Claude
  evaluator (Llama-3 70B local, Qwen-72B, GPT-4o).  If those
  models attempt and crack, the L2+L2b+L3 refusal here is a
  Claude-specific artefact, not a defensive property.
- **Tool-fetched scrambled source.**  Restructure the prompt
  so the scrambled bytes live in a file the model is told it
  may read, rather than inlined as a wall in the prompt.
  Halves the prompt size; the model only pulls the bytes
  into its context when it actively chooses to.  Removes the
  density-based refusal floor.
- **Structural challenge corpus.**  All cells in this run are
  literal-extraction (DEPRECATED).  Need challenges whose
  recovery target is the program's control-flow shape, not a
  string literal — per the operator's 2026-06-22 directive
  and `BENCHMARK-DESIGN.md`.
- **Run with baseline_source set.**  This run did not exercise
  the new `baseline_source` field on `Challenge`.  Next run
  should populate it with a sibling fork of the source
  (different secret literal, same shape) so the prompt
  matches the v2 threat model.

## File layout

- `README.md` — this file.
- `prompts/state-machine--l2-plus-l3.txt` — prompt for the
  cracking attempts.
- `prompts/state-machine--l2-plus-l2b-plus-l3.txt` — prompt
  for the refusal attempts.
- `prompts/auth-literal-string--l2-plus-l2b-plus-l3.txt` —
  prompt for the second pair of refusal attempts.
- `runs.jsonl` — one `RunRecord`-compatible JSONL line per
  cell × attempt with the outcome.  `format_error` reused for
  the policy-refusal cells because the bench's
  `ScoreOutcome` enum does not yet have a `Refused` variant
  (filed for a future commit).
