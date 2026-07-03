# Sandbox-execution defence — research note

> **Evidence framing corrected 2026-07-03.** This note originally
> cited the 2026-06-21 `computed-secret` bench cell as measured
> evidence for the threat below. That run was retracted in
> `crates/v2-babbleon-resilience-bench/CORRECTIONS.md` — its
> committed runs are archived-but-invalid data points, not a live
> measurement (`CORRECTIONS.md` itself flagged amending this doc
> as a required follow-up commit that never landed until now).
> The threat this note addresses does not need that bench cell to
> be real: it is a first-principles capability claim — any
> adversary with code-execution access can evaluate a
> constructed expression, independent of what any specific bench
> run measured — and the design below stands on that basis alone.

A tool-using adversary defeats *any* purely-textual scramble by
executing the code under analysis, not by reading it. Any
defence that relies on the source being *unreadable* fails the
moment the source becomes *executable* in the adversary's
environment — a scrambled Python file piped through `python3`
still runs correctly (that is the whole point of a working
obfuscator), and a computed value like
`chr(115) + chr(105) + chr(108) + chr(118) + chr(101) + chr(114) + chr(55)`
evaluates to `"silver7"` regardless of what identifiers or
whitespace around it look like. Layer 7's operator-marked-literal
mechanism (`docs/v2/string-literal-leak.md`) cannot address this
case at all — there is no literal to wrap in `secret(...)` when
the value is constructed at runtime from opaque pieces.

The threat is broader than just Python's `chr()`. An adversary
with any general-purpose execution surface (a shell, `curl`,
`sqlite3`, a REPL) has many ways to recover a value that was
computed-at-runtime under the legitimate program's actual state,
because obfuscation of the *source text* cannot change what the
*running program* computes.

This document records the threat model, why the obvious textual
defences don't address it, the candidate countermeasures, and a
recommended sequence.

## Threat model

The HANDOFF spec's adversary model assumes:

> The adversary uses BYOE scratchpad reasoning across many model
> calls — not single-shot in-context cracking.

An in-sandbox subagent adversary operationalises this concretely:
given a Bash tool that lets it run arbitrary shell commands
(including `python3 -c '...'`), any defence that relies on the
source being *unreadable* fails the moment the source becomes
*executable* in that sandbox — no amount of textual scrambling
changes what `python3` computes when handed the (still-valid)
scrambled program.

The threat is broader than just `python3`.  An adversary with
general-purpose tools (curl, jq, sqlite, even just `bash`) has
many ways to recover secrets that were intended to be
computed-at-runtime under the legitimate user's actual program
state.

## Worked example — why "no literals" doesn't help

```python
def auth(x):
    expected = chr(115) + chr(105) + chr(108) + chr(118) + chr(101) + chr(114) + chr(55)
    if x == expected:
        return True
    return False
```

Goal: find x for which `auth(x)` returns True. Answer:
`"silver7"`.

The source contains zero string literals — layer 7's
operator-marked-literal mechanism
(`docs/v2/string-literal-leak.md`) has nothing to wrap in
`secret(...)` here, so it cannot address this shape at all. Any
adversary with a Python interpreter recovers the answer in one
step regardless of which textual layers (L2/L3/L4/L5/L6/L12) are
active, because none of them change program semantics:

```
python3 -c 'print(chr(115)+chr(105)+chr(108)+chr(118)+chr(101)+chr(114)+chr(55))'
```

This is not a probabilistic claim that needs a crack-rate
measurement — it is exact: the scrambled program, by construction,
must still compute the same `chr()` concatenation the unscrambled
program does, or the obfuscator would have broken the program. An
adversary who can execute it sees exactly what the legitimate
runtime sees.

## Why the obvious defences don't work

### "Encrypt the source"

The `obfuscation-landscape.md` §7 already addresses this: the
runtime needs the plaintext to execute, so the decryption key
must be in the binary, so an attacker with the binary recovers
the plaintext.  Variants (whitebox crypto, TEEs, indistinguishability
obfuscation) are either unsuitable for consumer hardware or
academic-only.

### "Disable python3 in the adversary's sandbox"

Out of scope: Babbleon is a defensive obfuscation tool, not a
process-isolation system.  Sandbox composition is the operator's
deployment concern.

### "Refuse to run under a debugger / ptrace"

`obfuscation-landscape.md` §5 "Anti-analysis" addresses this:
detectable, brittle, doesn't help against a model that simply
runs the program without ptrace.

## Candidate countermeasures that might work

### C1: Runtime-only construction via daemon-served secrets

The legitimate program imports from `babbleon.runtime` and the
helper consults the daemon for any "computed" value.  Example:

```python
from babbleon.runtime import compute_secret

def auth(x):
    expected = compute_secret("password-1")
    return x == expected
```

`compute_secret("password-1")` round-trips the daemon over the
existing socket, receives the actual value (`"silver7"`), and
returns it.  An adversary running the source in their sandbox
calls the same function — but the daemon socket isn't there
(operator's host only), so `compute_secret` fails or returns a
honey value.

**Pros:**

- Composes cleanly with the existing daemon trust model.
- Cleanly addresses the computed-secret failure mode.
- Operator-marked (opt-in), so unmarked code keeps semantics.

**Cons:**

- Adds runtime latency (per-call socket round-trip; cache?).
- Operator workflow change: every secret has to live in the
  daemon's table.  Distribution / rotation discipline.
- An adversary who copies the daemon socket + per-host secret
  (i.e., escalated to operator-tier already) defeats this
  trivially.  But that adversary defeats everything; this
  defence does not regress against existing trust boundaries.

### C2: Sentinel-call control-flow guards

The legitimate program contains calls to
`babbleon.runtime.assert_in_trusted_tier()` that abort if the
preprocessor isn't active.  Compose with the existing
trusted-tier inode gate (HANDOFF item 9, "trust-tier inode gate
for python-shim"):

```python
from babbleon.runtime import assert_in_trusted_tier

def auth(x):
    assert_in_trusted_tier()
    expected = chr(115) + chr(105) + chr(108) + ...
    return x == expected
```

An adversary's sandbox doesn't satisfy the trust-tier check, so
the program aborts before reaching the literal-construction
code.

**Pros:**

- Builds on existing namespace-inode gate plumbing.
- Doesn't require per-secret daemon state.
- The check is fast (a syscall + comparison).

**Cons:**

- An adversary who knows the check exists can patch it out
  (delete the `assert_in_trusted_tier()` call) before running.
- An adversary who doesn't patch it out still sees the
  literal-construction code; running it under a stub
  `assert_in_trusted_tier()` (or just commenting the call) gives
  the answer.

C2 is weaker than C1 because the check is *near* the
sensitive code rather than *required by* the sensitive code.
Layered defences combine: C1 + C2 together raise the bar
meaningfully.

### C3: Reorder + execution markers (existing layer 4)

`docs/v2/structure-scrambling.md` already describes layer 4:
"chunk-level code reorder with word-tag markers."  The
preprocessor re-sequences source blocks at exec time using
embedded markers; the on-disk source is not directly runnable
in source order.

This addresses the failure mode by breaking *execution* on the
adversary's side: an adversary who runs the scrambled source
in their sandbox runs nonsense, because the chunk order is
shuffled.

**Pros:**

- Already specified in the v2 design; no new design work.
- Defeats trivial copy-paste-into-python3 attacks.

**Cons:**

- A determined adversary parses the markers (which are public
  per Kerckhoffs) and reconstructs the original order, then
  runs.  C3 alone is brittle; combines with C1 / C2 / layer 7
  for layered defence.
- Implementation complexity: layer 4 is the most invasive of
  the v2 layers (touches the AST level, not just the lexical
  level).

### C4: Honey computations + behavioural detection

Inject decoy computations (cf. layer 5 "junk decoys" already in
the design) that look like real secret reconstructions.  An
adversary running the scrambled source either (a) gets a honey
value that triggers an operator-side tripwire when the adversary
tries to use it, or (b) has to filter the honey from the real,
which is expensive per rotation.

**Pros:**

- Reuses existing honey + tripwire infrastructure (v1 / v2).
- Increases the adversary's cost per rotation rather than
  defeating the attack outright (the consistent v2 framing).

**Cons:**

- Honey values that look-like-secrets are hard to generate
  automatically.  Operator-marked, like layer 7.
- Doesn't actually stop the literal-construction execution;
  just adds confusion.

## Recommended sequence

This document's qualitative call, from the candidate-countermeasure
analysis above: **C1 is the right primary defence; C3 is the right
secondary defence; C2 and C4 are supporting controls.**

Sequence:

1. **C1: Runtime-only construction.**  Highest leverage; cleanly
   addresses the failure mode.  Same daemon-trust model as
   layer 7.  ~300 LOC + tests + protocol-schema bump.
2. **C3: Chunk reorder (layer 4).**  Already on the phase-4
   roadmap; C1 fits inside its trust framing.  Bigger
   implementation effort (AST-level work).
3. **C2: Trust-tier asserts.**  Folds into the existing
   namespace-inode gate; small.
4. **C4: Honey computations.**  Bench-driven design once C1 +
   C3 land.

After C1 lands, add a bench challenge `computed-secret-via-
runtime` that uses `compute_secret(...)` instead of the raw
`chr()` construction. Expected outcome, by the same
first-principles reasoning as the worked example above: crack
fraction drops once the construction routes through the daemon
rather than appearing in the source at all. Note this is a
prediction to verify with a proper re-run under
`BENCHMARK-DESIGN.md`'s requirements (per-cell N>=5, literal-free
corpus), not a result already in hand — the `secret-wrapped`
challenge and the 2026-06-22 layer-7-prototype run that exercised
it are both retracted in `CORRECTIONS.md`, which explicitly directs
against citing that run's numbers as evidence anywhere.

## What this does NOT close

- **Operator-tier-equivalent adversaries.**  An attacker who has
  the per-host secret AND the daemon socket defeats everything.
  Babbleon's trust boundary is the daemon socket + the per-host
  secret; defeating both means defeating Babbleon, by design.
- **Side-channel timing.**  An adversary who runs the legitimate
  binary and observes execution patterns may leak information
  about which path is taken on which input.  Out of scope;
  filed under timing-side-channels.md (TBD).
- **Patched binaries.**  An adversary who can modify the
  legitimate binary itself (insert `print(secret)` before the
  comparison) defeats this and everything else.  Binary integrity
  is upstream of Babbleon; out of scope.

## Cross-references

- `docs/v2/string-literal-leak.md` — sister doc addressing
  layer 7 (literal-leak defence).  This doc is the orthogonal
  failure mode.
- `docs/v2/structure-scrambling.md` Layer 4 — pre-existing
  design for chunk reorder; C3 here.
- `docs/v2/obfuscation-landscape.md` §5 / §7 — addresses the
  "why not just X" alternatives.
- `crates/v2-babbleon-resilience-bench/runs/2026-06-21-claude-opus-4-7-subagent/`
  — the retracted run that originally prompted this note; see its
  `INVALIDATED.md` and `crates/v2-babbleon-resilience-bench/
  CORRECTIONS.md` for why its numbers are not citable evidence.
- HANDOFF item 9 (trust-tier inode gate) — the plumbing C2
  composes onto.
