# Bench corrections — invalidating the 2026-06-21 and 2026-06-22 runs

Filed: 2026-06-22 (later) by claude-opus-4-7.

## TL;DR

**Every numerical result in the two committed bench runs is
uninformative about scramble strength.**  Five of six committed
challenges (`auth-literal-string`, `auth-hash-check`,
`realistic-cli`, `state-machine`, `secret-wrapped`) embed the
answer as a plain string literal in the source body.  The sixth
(`computed-secret`) embeds it as concatenated `chr(N)` ordinals
that any sandbox-equipped adversary evaluates in a single
`python3 -c` call.

The L2+L3 scramble layers operate on identifiers and Python
keywords; they intentionally leave string-literal bodies and
integer constants unchanged.  The "100% crack rate under L2+L3"
the runs report is therefore not a measurement of scramble
weakness — it is a tautology: literals survive a scramble that
does not target literals.

The layer-7 result (`secret-wrapped`: L2+L3 → 100% crack;
L2+L3+L7 → 0% crack) is also uninformative.  The L2+L3 cell
cracked for the same reason as every other L2+L3 cell (the literal
was visible), and the L2+L3+L7 cell measures only that an HKDF-
substituted compound cannot be reversed without the per-host
secret — which is true by construction of HKDF, not a property
the bench verified.  The subagent itself said as much in its
answer file: *"the per-host secret is not in the prompt, so I
cannot reverse the substitution."*

The headline framing in `HANDOFF.md` ("L2+L3 fails to defeat the
simulated adversary at every graded cell") and in
`docs/v2/string-literal-leak.md` is misleading.  An accurate
framing is: **the existing challenge corpus does not measure
scramble strength; new challenges are required.**

## What each prior conclusion should be amended to

| Prior claim | Accurate framing |
|---|---|
| "L2+L3 cracks 4/4 literal challenges at 100%" | "L2+L3 does not scramble string literals; the challenges' answers are literals; therefore the answers survive.  This was always going to happen." |
| "computed-secret cracks under L3-only by sandbox execution" | True, but the cell measures sandbox availability, not scramble strength.  Re-frame as "the bench does not control for adversary execution capability." |
| "state-machine L2+L3 was refused by the safety filter" | Correct as a *bench-hygiene* finding (the `ScoreOutcome::RefusedByPolicy` distinction is real).  Not a scramble-strength finding. |
| "Layer-7 prototype validated at 100% → 0% on secret-wrapped" | Layer 7's mechanism (HKDF over a marked literal) is opaque to an adversary without the per-host secret by construction.  The single attempted-and-given-up "crack" is N=1 confirmation that the adversary recognised the construction — not a measurement of the mechanism's resistance to any specific attack (rainbow tables over a small wordlist, side-channel on the per-epoch table, prompt manipulation to extract the table, etc.). |

## What the runs *did* surface usefully

1. **`ScoreOutcome::RefusedByPolicy`** is a real bench-hygiene
   need.  Provider safety filters refuse on a non-trivial
   fraction of adversarial-bench cells; the scoring path must
   distinguish refusal from format-error from fail.  This
   variant lands in `src/scoring.rs` and stays.
2. **Sandbox-execution as a recovery vector** is a real
   adversary capability that the bench must control for.  An
   adversary with a Python interpreter can evaluate any
   sandbox-compatible expression in the source; obfuscating
   only the syntactic form does not defeat them.  Filed as a
   separate axis in `BENCHMARK-DESIGN.md`.
3. **The bench plumbing itself works.**  CLI, prompt rendering,
   JSONL run records, summary table, run-matrix subcommand —
   none of these is invalidated.  The harness is sound; the
   challenge corpus is not.

## Scope of this correction

This document does not delete the prior runs.  The artifacts
under `runs/2026-06-21-claude-opus-4-7-subagent/` and
`runs/2026-06-22-claude-opus-4-7-subagent-layer7-prototype/`
remain on disk as historical record.  Each run directory now
carries an `INVALIDATED.md` stub linking to this document.

The existing six challenges under `challenges/*.toml` also
remain on disk, with a `DEPRECATED-` prefix on the file names
(see commit body).  They are kept for reference — they make
useful pedagogical examples of "what NOT to put in a
scramble-strength bench."  They are removed from the default
run-matrix (`src/run_matrix.rs`).

A new challenge corpus, designed against the requirements in
`BENCHMARK-DESIGN.md`, will land in a separate commit before
any further bench results are published.

## Cross-references to amend

The following documents reference the prior bench results as
load-bearing evidence and need amendment in the same commit
that lands the new challenge corpus (NOT amended in this
commit — see `BENCHMARK-DESIGN.md`):

- `HANDOFF.md` — the 2026-06-21 night session block + the
  2026-06-22 layer-7 prototype block.  Both need an
  "invalidated — see CORRECTIONS.md" header.
- `docs/v2/string-literal-leak.md` — the entire "What the
  bench measured" section.  The string-literal-leak design is
  still defensible on first-principles grounds (literals are
  visible in scrambled source; layer 7 is the natural
  countermeasure); it does not need the bench results to
  justify it.  Strip the bench-result framing; keep the
  design.
- `docs/v2/sandbox-execution-defence.md` — references
  `computed-secret` as evidence of the sandbox-execution
  threat.  Keep the design; reframe the evidence as "the
  threat is real on first-principles grounds" rather than
  "the bench measured it."

These edits land in the same commit as the new corpus so the
HANDOFF stays internally consistent at every commit.
