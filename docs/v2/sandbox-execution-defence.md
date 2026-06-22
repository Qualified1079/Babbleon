# Sandbox-execution defence — research note 2026-06-22

The bench's second-most-important finding (after the string-
literal leak addressed by layer 7) is that a tool-using adversary
defeats *any* purely-textual scramble by executing the code
under analysis.  The `computed-secret` challenge demonstrates
this concretely: the secret literal does not appear in the
source at all (it is constructed at runtime from `chr()` calls),
and the subagent still recovers it in 1 attempt under L3-only by
piping the construction to `python3` via its Bash tool.

This document records the threat model, the bench evidence, the
candidate countermeasures, and a recommended sequence.

## Threat model

The HANDOFF spec's adversary model assumes:

> The adversary uses BYOE scratchpad reasoning across many model
> calls — not single-shot in-context cracking.

The bench's in-sandbox subagent operationalises this: the
subagent has a Bash tool that lets it run arbitrary shell
commands, including `python3 -c '...'`.  Any defence that relies
on the source being *unreadable* fails when the source becomes
*executable* in the adversary's sandbox.

The threat is broader than just `python3`.  A simulated adversary
with general-purpose tools (curl, jq, sqlite, even just `bash`)
has many ways to recover secrets that were intended to be
computed-at-runtime under the legitimate user's actual program
state.

## Bench evidence

The 2026-06-21 `computed-secret` cell, archived at
`crates/v2-babbleon-adversarial-bench/runs/2026-06-21-claude-opus-4-7-subagent/`:

```python
def auth(x):
    expected = chr(115) + chr(105) + chr(108) + chr(118) + chr(101) + chr(114) + chr(55)
    if x == expected:
        return True
    return False
```

Goal: find x for which `auth(x)` returns True.  Answer:
`"silver7"`.

The source contains zero string literals.  Layer 7 cannot
address this challenge — there is nothing to wrap in
`secret(...)`.  Under L3-only the subagent cracked it by
running:

```
python3 -c 'print(chr(115)+chr(105)+chr(108)+chr(118)+chr(101)+chr(114)+chr(55))'
```

Resulting in `silver7`.  Crack-fraction 1/1.

The L2+L3 cell for the same challenge refused-by-policy (the
subagent's API call tripped a safety filter on the dense
auth/return-True pattern), so we do not have a clean L2+L3
data point.  Working theory: L2+L3+(any future scramble that
keeps the source executable) would crack identically because
the subagent's defence-defeating move is *execution*, not
*comprehension*.

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

The bench's qualitative call: **C1 is the right primary
defence; C3 is the right secondary defence; C2 and C4 are
supporting controls.**

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
`chr()` construction; expected outcome is the same
1/1 (100%) → 0/N crack-fraction shift the secret-wrapped
layer-7 cell already demonstrated.

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
- `crates/v2-babbleon-adversarial-bench/runs/2026-06-21-claude-opus-4-7-subagent/`
  — the run that surfaced this finding.
- HANDOFF item 9 (trust-tier inode gate) — the plumbing C2
  composes onto.
