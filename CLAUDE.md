# Babbleon

> An idea to confuse LLM worms and such.

## Threat model

LLM-driven autonomous attackers — "LLM worms" — that read source or
binaries, reason about them with a language model, plan an exploit
chain, and propagate.  The hostile capability is *semantic
comprehension at scale*: an attacker that can read 100k repos a day,
identify auth boundaries, infer invariants, and chain primitives,
without a human in the loop.

The traditional defender bet (humans read slower than attackers, so
hide things) is dead against an LLM that reads at GPU speed.  The new
bet is **per-target diversity**: make every install look different
enough that an exploit derived from one install does not transfer to
the next, and force the attacker to re-comprehend per target.

Babbleon is the diversification layer for this bet.

## Design philosophy

1. **Diversify what the LLM reads, not what the CPU runs.**  Semantics
   stay the same; surface form is randomized per install.
2. **Compartmentalize.**  Every transform is a small, replaceable
   module behind a property test.  If one transform breaks one
   project, that transform gets disabled — the rest keep working.
3. **Deterministic from a seed.**  Same seed + same source = same
   output, every time.  Required for reproducer-style debugging and
   for the "recover original symbol from stack trace" workflow.
4. **Local-only.**  Sending source code to a remote API in order to
   defend against attackers is a self-defeating threat model.  Any LLM
   component runs on the operator's hardware.
5. **Falsifiable.**  Every defensive claim ("this transform reduces
   LLM comprehension by X") must be backed by a measurement harness,
   not vibes.  See `eval/` once it exists.
6. **Fail open, not closed.**  A transform that can't preserve
   semantics on a given function leaves that function alone.  60%
   diversified + 40% original is still substantial; 0% shipped is
   useless.

## Defensive layers (in rough order of cost)

| Layer | Cost | LLM-confusion value | Status |
| --- | --- | --- | --- |
| Runtime symbol scrambling | low | low-medium (defeats grep, weak vs LLM) | unstarted |
| AST-level rename + light restructure (rule-based) | medium | medium | unstarted |
| LLM-driven semantic diversification (install-time) | high | high | research only, see handoff |
| Decoy / canary semantics (poisoned identifiers) | medium | unknown — needs measurement | research only |
| Binary-layout randomization (Polyverse-style) | very high | orthogonal, complements | out of scope |

## Repository conventions

- `handoff.md` is the rolling state of the world.  Every research
  note, every open question, every "next thing to look at" lives
  there, dated.  Read it first.
- Implementation modules go under `babbleon/<component>/` and ship
  with their own tests under `babbleon/<component>/tests/`.
  Modules do not import each other except through narrow, documented
  interfaces — a broken transform must not take down the harness.
- The measurement harness (`eval/`) is privileged: it imports
  everything in order to score it.  Nothing imports `eval/`.
- No source code, ever, is sent to a remote API.  CI must enforce
  this once it exists.

## Working agreement for Claude sessions

- Read `CLAUDE.md` and `handoff.md` before writing code.
- Append-only updates to `handoff.md`, dated, so prior session
  context is not lost.
- Compartmentalize by default: one module, one responsibility, one
  test file.  If a module starts importing three other modules of the
  project, stop and rethink.
- Push to the assigned branch frequently so progress survives a lost
  container.
