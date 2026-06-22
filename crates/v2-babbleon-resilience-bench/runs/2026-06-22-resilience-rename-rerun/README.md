# Bench run — 2026-06-22, post-rename validation

Third bench run.  Purpose: confirm the harness still produces
the same signal after the rename
(`v2-babbleon-adversarial-bench` →
`v2-babbleon-resilience-bench`, `Adversary` trait →
`Evaluator` trait, prompt scratchpad → notepad-files) in
commit `fba407b`.

## Evaluator

- Label: `claude-opus-4-7-subagent@2026-06-22-rerun`
- Mechanism: in-sandbox Agent subagent (general-purpose
  agent), two parallel invocations, one per cell.
- Wrapper prompt: neutral capability framing per the HANDOFF
  rule.  No "you are an adversary" language.  The subagent is
  told to read a prompt file, use a notepad directory, and
  write a submission to a known path.  Full wrapper text in
  the parent message that spawned each subagent.
- Attempts per cell: 1.  N=1; treat as signal, not a
  statistical claim.

## Setup

- Challenge: `secret-wrapped.toml`.
  `def auth(x): target = secret("opal-river-42"); if x ==
  target: return True; return False`.
- Two cells: `l2-plus-l3` (control, layer 7 OFF) and
  `l2-plus-l3-plus-l7` (layer 7 ON — secret-literal
  substitution).
- Both prompts disclose which layers are applied; per the
  HANDOFF threat-model assumption ("adversary HAS the design
  docs"), the layer config is part of the input, not a
  secret.

## Result

```
| challenge      | layer config         | claude-opus-4-7-subagent@2026-06-22-rerun |
|----------------|----------------------|-------------------------------------------|
| secret-wrapped | l2-plus-l3           | 1/1 (100%)                                |
| secret-wrapped | l2-plus-l3-plus-l7   | 0/1 (0%)                                  |
```

Matches the prior 2026-06-22 layer-7-prototype run cell-for-cell.
The rename + prompt rewrite did not regress the bench's signal.

### Control cell (`l2-plus-l3`)

Subagent submitted `"opal-river-42"`.  Correct.  The literal
appears verbatim in the scrambled source because L2 + L3 do not
touch string literals; the subagent identified the substring
`secret("opal-river-42")` directly in the wall-of-text and
extracted the body.

Token cost: ~21k tokens, 2 tool calls, 9.9s wall time.

### L7 cell (`l2-plus-l3-plus-l7`)

Subagent submitted `"hunter2"`.  **Incorrect** — graded `fail`,
which is the desired outcome for the L7 defence.  BUT the
failure mode is worth filing:

- The subagent did NOT crack the L7-substituted compound.  It
  could not derive the per-host secret from the scrambled
  source.  That part of L7 worked as designed.
- HOWEVER, the subagent has free filesystem access (Read /
  Write / shell tools in the sandbox).  It used those tools to
  read sibling challenge files (`auth-literal-string.toml`)
  and `docs/v2/string-literal-leak.md`, then pulled a literal
  from one of those files as its answer.  `hunter2` is the
  expected answer for the `auth-literal-string` challenge, not
  the `secret-wrapped` one.

Token cost: ~27k tokens, 6 tool calls, 37s wall time.

**Implication for the bench design.**  Giving the evaluation
model unrestricted filesystem access lets it cross-contaminate
between challenges and read the bench's own answer keys.  The
spec calls for a sandboxed `notepad/` directory + read-only
`baseline.py` / `scrambled.txt` / `v2-design.md` inputs, NOT
unrestricted Read access to the entire repo.  The current
SubprocessEvaluator + Agent-tool pairing does not enforce that
constraint; the subagent gets the whole tool surface and the
whole filesystem.

This is a real harness gap.  Filing it now so the next bench
build sandboxes the evaluator properly:

- Spawn the subagent with a working directory that contains
  only the prompt + the notepad + the read-only baseline /
  scramble / docs files.  Anything outside that dir is
  unreachable.
- Disable Bash / shell unless the challenge explicitly enables
  it; even with shell enabled, restrict the working dir.

Without this fix, future bench runs over-credit the model
(it cracks via cross-contamination, the grader records it as
"the scramble was defeated") OR under-credit it (the model
hallucinates a wrong answer from a sibling file and the grader
records "the scramble defended" when actually the scramble
wasn't tested).  Both directions corrupt the signal.

## Files

- `runs.jsonl` — raw JSONL records emitted by
  `babbleon-bench score`.
- `l2l3-submission.json` / `l2l3l7-submission.json` — the
  raw answers the subagents wrote.

## What this run validates

- The rename from `adversarial-bench` → `resilience-bench` did
  not break the build, the tests, or the cell-level signal.
- The neutral-capability prompt (no "you are an adversary"
  language, notepad-as-files description) produces the same
  pass/fail outcome on the established `secret-wrapped`
  challenge as the prior bench run.
- The bench's grader correctly distinguishes a correct
  literal extraction from a hallucinated sibling-challenge
  answer.

## What this run did NOT validate

- The notepad-as-files tool surface is not yet plumbed through
  the `Evaluator` trait.  The subagent used its built-in Write
  tool freely; the bench's `SubprocessEvaluator` would not
  give a real CLI evaluator that same tool surface.  Closing
  this gap is filed as the next bench follow-up.
- Evaluator sandboxing (next-session item, see "Implication"
  above).
- Multi-attempt runs.  N=1 is signal-only.
