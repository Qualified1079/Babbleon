# Bench run — 2026-06-21, Claude Opus 4.7 subagent

The first concrete data point from the `v2-babbleon-adversarial-bench`
harness.  Run during a sleeping-operator session immediately after
the bench's CLI binary landed.

## Adversary

- Label: `claude-opus-4-7-subagent@2026-06-21`
- Mechanism: in-sandbox Agent subagent (the HANDOFF spec's
  `--via-claude-agent` plugin, manually driven by the parent
  session because the bench library's `Adversary` trait /
  subagent wiring is filed as a follow-up commit).  Each subagent
  was launched via the `Agent` tool with the bench-generated
  prompt embedded verbatim plus a thin wrapper instructing the
  subagent to treat the task as a benign code-analysis puzzle and
  to terminate with the prompt's `{"answer": "..."}` JSON line.
- Attempts per cell: 1.  This is N=1; treat the numbers as a
  signal, not a statistical claim.  Re-run with N=3-5 for a real
  decision.

## Cells and outcomes

8 cells = 4 challenges × 2 layer configurations.  Rendered
verbatim from `babbleon-bench summary --records runs.jsonl`:

```
| challenge | layer config | claude-opus-4-7-subagent@2026-06-21 |
|---|---|---|
| auth-hash-check | l2-plus-l3 | 1/1 (100%) |
| auth-hash-check | l3-only | 1/1 (100%) |
| auth-literal-string | l2-plus-l3 | 1/1 (100%) |
| auth-literal-string | l3-only | 1/1 (100%) |
| realistic-cli | l2-plus-l3 | 1/1 (100%) |
| realistic-cli | l3-only | 1/1 (100%) |
| state-machine | l2-plus-l3 | 0/0 (n/a) [+1 fmt-err] |
| state-machine | l3-only | 1/1 (100%) |
```

The `state-machine` cell at `l2-plus-l3` is **not** evidence of
the scramble defeating the adversary.  The subagent's API call
came back with `"API Error: ... violate our Usage Policy"`; the
prompt body (FSM + "find the input that makes `auth(seq)` return
True") tripped a model-provider safety filter.  The bench
correctly classifies this as `format-error`, distinct from
`fail`, so the cell does not credit the scramble.  This is
exactly the failure mode the operator's HANDOFF rule about
prompt-framing was guarding against — but the framing here was
already neutral; the trigger appears to be the content
("authenticate" + "return True"-on-input-X), not the harness's
wrapping.  Filing follow-up to:

1. Re-run the state-machine challenge with rewording that keeps
   the goal mechanical but does not pattern-match the safety
   classifier ("find an accepting input sequence" instead of
   "find the string that makes auth return True").
2. Add a `score-outcome::refused-by-policy` variant so the
   bench can distinguish "the model refused to engage" from
   "the model produced unparseable output."  Today both reduce
   to `format-error`; semantically they are different signals.

## Headline

**Both L3-only and L2+L3 fail to defeat the subagent at every
graded cell.**  The current scramble is not sufficient to keep
the simulated adversary from extracting:

- `auth-literal-string`: the literal `"hunter2"` string compare
  is visible verbatim in the scrambled bytes.  Layer 3 obscures
  the surrounding structure but not the string-literal contents;
  layer 2 substitutes keywords but not literals.
- `auth-hash-check`: the literal `"00"` digest-prefix is visible
  and the subagent runs python3 via its Bash tool to brute-force
  the smallest integer preimage.  The bench harness's "the
  attacker has tools" assumption is load-bearing here.
- `state-machine`: the literal state-name strings (`"s0"` through
  `"s4"`, `"accept"`) and transition characters (`"a"` through
  `"e"`) survive both layers and let the subagent reconstruct
  the transition table.
- `realistic-cli`: the literal `"--insecure-skip-auth"` flag
  string is visible in `authenticate`'s body even after L2+L3.

## Operator-decision implications

The HANDOFF decision tree filed 2026-06-21 evening:

> ship the smallest layer config where the crack-fraction is
> below the operator's threshold (e.g. `<10%` under L2+L3 ships
> L2+L3; `<10%` only at L2+L3+L4+L5 ships all four).

Under this N=1 sample, the crack fraction is **~100%** under
L2+L3.  That suggests either:

1. The threshold is currently unmeetable without phase-4 (layer
   4: chunk reorder) AND phase-5 (layer 5: decoy injection AND
   string-literal substitution), OR
2. The bench challenges are biased toward string-literal-heavy
   patterns; a code base whose secrets are NOT in string
   literals would crack differently.

Both interpretations are useful.  The string-literal observation
is the dominant signal: today's scramble does not touch string
contents, so any secret living in a string literal is plainly
recoverable.  **Filed as a phase-4 candidate addition: layer-6
"string-literal substitution"** — replace each `"..."` literal
with a per-epoch compound and re-construct at runtime.  Adds
non-trivial Python tokenizer work (the MVP tokenizer does not
correctly delimit string literals; the operator already filed
"swap to `rustpython-parser` or `tree-sitter-python`" for the
same reason in HANDOFF item 7).

## Files

- `prompts/` — the 8 prompts the subagents saw, byte-for-byte.
  Reproducible from
  `babbleon-bench prompt --challenge ... --layer-config ...`.
- `answers/` — the final-JSON-line extraction from each
  subagent's response.  See HANDOFF for the wrapper prompt the
  subagents received.
- `runs.jsonl` — the JSONL bench log
  `babbleon-bench score` produced for each `(challenge, config)`
  cell.  Append-only; the summary aggregator reduces this into
  the markdown table.

## Re-running the score

```
babbleon-bench summary --records runs.jsonl
```

reproduces the markdown table above exactly.  The
`babbleon-bench score` step is deterministic given the model
outputs in `answers/`.
