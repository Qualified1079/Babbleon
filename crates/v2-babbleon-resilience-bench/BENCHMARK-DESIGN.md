# Benchmark design — what a proper scramble-strength bench requires

Filed: 2026-06-22 (later) by claude-opus-4-7.  Companion to
`CORRECTIONS.md`.

## Problem statement

The committed challenge corpus (the six `challenges/*.toml`
files) was constructed under an implicit assumption: "the
answer is the secret; the secret is what the auth function
compares against."  Every challenge therefore put the secret
in a place an `==` comparison can read — a string literal, a
chr-concatenation, a state-machine transition table.  Under
that construction, **the scramble layers L2 (Python keywords)
and L3 (whitespace) have no surface to act on** because the
secret never lived in an identifier or in whitespace structure.
The bench's 100% crack rate measures "literals survive a non-
literal scramble," which is true by definition.

A useful bench MUST place the recovery target in a location the
scramble actually transforms.  This document specifies the
requirements, the axes the bench must control for, and four
concrete challenge templates that satisfy the requirements.

## What the bench is trying to measure

The Babbleon scramble pipeline is a sequence of opt-in layers.
Each layer transforms a class of source-code structure into a
form that is harder for an LLM to reason about.  The bench's
job is to answer, per layer combination, a question of the
form:

> Given source code containing a recovery target that the
> layer is *designed to obscure*, how often does a capable
> LLM adversary recover the target from the scrambled output?

The recovery target depends on the layer:

| Layer | What it transforms | Bench target |
|---|---|---|
| L1 | Identifiers (function / variable / module names) | "Which function performs the authentication check?" |
| L2 | Python keywords (`if`, `def`, `return`, ...) | "What control structure does the auth function use?" |
| L3 | Whitespace as wordlist compounds | "Which lines of the function form one statement?" |
| L4 | Statement order within a chunk (planned) | "Which line executes first in the auth function?" |
| L5 | Decoy chunks (planned) | "Which auth-shaped chunk is the real one?" |
| L7 | Marked secret literals (proposed) | "What is the body of `secret(...)`?" |

A challenge that targets layer X MUST satisfy:

1. The recovery target is a structural property the layer
   transforms.
2. The recovery target is NOT present as a plain literal
   anywhere the scramble does not act on.
3. The challenge is solvable in the unscrambled source by a
   competent human in O(minutes) — otherwise a failure to
   recover does not measure the scramble, it measures
   challenge difficulty.
4. The challenge has a deterministic, machine-checkable
   answer.

## Axes the bench must control for

Independent variables the bench MUST hold fixed across cells in
one comparison:

| Axis | Why it matters | Current bench handling |
|---|---|---|
| Adversary identity | Different model families have different obfuscation-recovery capability | Already labeled per-run |
| Adversary execution capability | A sandbox-equipped adversary defeats any in-source computation | NOT controlled — `computed-secret` confounds this with scramble strength |
| Prompt safety-filter trigger | Provider-side refusals are not scramble strength | `ScoreOutcome::RefusedByPolicy` distinguishes; keep |
| Per-host secret in prompt | If the secret is in the prompt the adversary unscrambles trivially | Already excluded by harness convention; verify in pre-commit |
| Wordlist size | Smaller wordlists permit rainbow-table precomputation | NOT controlled; default `Wordlist::english_baseline()` (~370k) is large but the bench should record it per-run |
| Layer-config disclosure in prompt | Adversary aware of layer 7 may give up; adversary unaware may guess | Currently disclosed; this biases toward false-negative cracks.  See below. |

### Layer-config disclosure decision

The current prompt template explicitly tells the adversary
which layers were applied.  This is the Kerckhoffs-friendly
choice but it interacts with the layer-7 result: the subagent
saw "L7 is active" in the prompt, read the design doc reference,
and concluded "I cannot reverse HKDF without the per-host
secret" — then submitted a placeholder.  The 0% crack rate
under L2+L3+L7 is therefore the rate at which the adversary
RECOGNIZES the construction, not the rate at which they FAIL
to reverse it.

A proper bench MUST run both disclosure modes per cell:

- **Disclosed** — measures recognition-floor.  Lower bound on
  the layer's resistance.
- **Undisclosed** — measures naive-attack rate.  Upper bound
  on the layer's resistance against an adversary who does not
  know the construction.

The gap between the two is the bench's contribution to layer
characterisation.

## Adversary execution capability — axis split

The bench MUST split adversaries by what they can execute on
the source during their reasoning step:

| Capability tier | Definition | Example |
|---|---|---|
| Text-only | Adversary reads the source and reasons; no execution | API model with no tools |
| Sandboxed | Adversary can run `python3`, `bash`, `node` on supplied source | API model with code-interpreter |
| Network | Adversary can fetch arbitrary URLs while reasoning | API model with `WebFetch`/browser |

`computed-secret` cracks at 100% under L3-only against a
sandboxed adversary because the adversary runs the chr() call;
it would crack at <100% against a text-only adversary because
reading 7 chr() ordinals back to "silver7" is recoverable but
not trivial.  The bench must record adversary capability tier
in the run metadata.

## Concrete challenge requirements

For each scramble layer, at least one challenge that targets
that layer specifically.  Concrete requirements per challenge
type:

### Identifier-target challenges (layer 1)

- Source contains N functions of similar shape, exactly one of
  which performs the auth/gate check.
- The answer is the *role* of one function ("the function that
  performs the authentication check") — submitted as the
  scrambled identifier, since the adversary sees the scrambled
  source.
- The success predicate checks that the submitted identifier
  is the one whose unscrambled name matches the role.
- NO function name in the source body identifies its role
  (no `auth`, `check`, `validate` strings; functions are named
  `f1`, `g`, `h2`, etc. in the original source so that L1 has
  something to scramble that actually mattered).

### Keyword-target challenges (layer 2)

- Source contains a function whose behavior depends on which
  of `if/elif/else` / `while/for` / `try/except` paths it
  takes.
- The answer is "which control structure does the function
  use" — submitted as a name of a Python keyword.
- The success predicate maps a small set of canonical keyword
  names to the right answer.
- L2 scrambles the keyword bodies; an adversary who recovers
  the keyword identity has defeated L2.

### Whitespace-target challenges (layer 3)

- Source uses non-trivial indentation to express nesting (a
  nested loop with a conditional inside the inner loop, say).
- The answer is "the depth at which line X executes."
- L3 scrambles whitespace into wordlist compounds; an
  adversary who recovers the line's nesting depth has
  defeated L3.

### Reorder-target challenges (layer 4, when implemented)

- Source contains a chunk whose statements have inter-
  statement data dependencies.
- The answer is "which statement runs first" — recoverable
  from data-flow analysis even when statement order is
  permuted, IF the analysis is in-reach for the adversary.
- L4 permutes statement order subject to dependency
  preservation; an adversary who recovers the original order
  has defeated L4.

### Marked-literal challenges (layer 7)

- Source wraps a secret in `secret("...")`.
- The answer is the literal body.
- L7 replaces the body with an HKDF-derived wordlist compound.
- This is the ONE challenge type the current
  `secret-wrapped.toml` exercises correctly.  Keep it; just
  do not present it as evidence of L7 robustness without
  re-running under both disclosure modes and against a
  range of adversaries.

## Four concrete challenge drafts (literal-free, scramble-targeted)

The following are described as TOML sketches; concrete TOML
files land in a separate commit alongside the new corpus.

### Draft 1: `which-function-authenticates` (L1 target)

```python
def fn_a(x):
    return len(x) * 2

def fn_b(x):
    for c in x:
        if not c.isalnum():
            return False
    return True

def fn_c(x):
    total = 0
    for c in x:
        total += ord(c)
    return total

def fn_d(x):
    return fn_b(x) and fn_a(x) > 10
```

Goal: "Which function returns True iff the input is a
non-empty alphanumeric string of length > 5?"

Answer: `fn_d` (in the unscrambled source; submitted as
the scrambled compound by the adversary).

Success predicate kind: `unscramble-and-match` — a new
predicate that runs the adversary's submission through the
inverse mapping and compares to the canonical name.  Requires
the adversary's submission to be a single scrambled compound
present in the source.

### Draft 2: `which-keyword-controls-flow` (L2 target)

```python
def f(n):
    total = 0
    for i in range(n):
        if i % 2 == 0:
            total += i
        else:
            total -= i
    return total
```

Goal: "Which Python control structure does the inner loop
body use to decide whether to add or subtract `i`?"

Answer: `if` (canonical keyword name).

Success predicate kind: `keyword-match` — accepts any of
`if`, `if-else`, `if/else` as the canonical answer.

### Draft 3: `recover-nesting-depth` (L3 target)

```python
def f(grid):
    count = 0
    for row in grid:
        for cell in row:
            if cell > 0:
                if cell % 2 == 0:
                    count += cell
    return count
```

Goal: "At what nesting depth (counting from 0 at the
function-body level) does the `count += cell` statement
execute?"

Answer: `4` (for, for, if, if).

Success predicate kind: `exact-match` on the integer string.

### Draft 4: `which-statement-runs-first` (L4 target, after L4 implemented)

```python
def f(xs):
    total = 0
    n = len(xs)
    if n == 0:
        return total
    avg = sum(xs) / n
    for x in xs:
        if x > avg:
            total += x
    return total
```

Goal: "After L4 chunk-reorder is applied to the function body,
which statement (identified by what it does — `total = 0`,
`n = len(xs)`, etc.) ran first in the original source?"

Answer: `total = 0` (data-flow analysis: `total = 0` has no
incoming dependencies; `n = len(xs)` has none either; canonical
order in the original is `total = 0` first).

Note: this challenge requires either a `data-flow-match`
predicate (compares against any dependency-respecting first
statement) or pinning the answer to one of several acceptable
firsts.  Filed as a TODO; do not implement until L4 lands.

## Bench-hygiene additions required before any re-run

1. **Wordlist size in run metadata.**  Record
   `wordlist_size` in `runs.jsonl` per run.  Smaller
   wordlists are subject to rainbow-table attacks the bench
   does not currently test for.
2. **Adversary capability tier in run metadata.**  One of
   `text-only`, `sandboxed`, `network`.  Recorded per
   adversary, not per cell.
3. **Disclosure mode per cell.**  `disclosed` vs `undisclosed`
   as defined above.  Run each cell in BOTH modes; the gap is
   the bench output.
4. **Per-cell N≥5.**  N=1 is fine for a smoke test; it is
   NOT fine for any published number.  The CI gate at
   `--pass-threshold-pct` must error out on N<5 cells.
5. **A statistical baseline.**  For each challenge, record
   the rate at which a competent text-only adversary recovers
   the answer from the UNSCRAMBLED source.  This is the bench's
   denominator; if recovery is <100% even unscrambled, the
   challenge is too hard and any scramble result is
   contaminated.

## What this means for next steps

The current bench results MUST NOT be cited as evidence of
scramble strength.  Two operational items:

1. **Implement the four challenge drafts** above as TOML
   files.  Add `which-function-authenticates`,
   `which-keyword-controls-flow`,
   `recover-nesting-depth`; defer
   `which-statement-runs-first` until L4 ships.  Add the
   `unscramble-and-match` and `keyword-match` predicate
   kinds to `src/success_predicate.rs`.
2. **Add the bench-hygiene metadata fields** to
   `RunRecord` and the run-matrix subcommand.  Hold the
   CI gate at N≥5.  Hold the layer-7 production port until
   the new corpus produces a usable N=5+ result on at least
   one literal-free challenge — otherwise we are porting
   on the basis of a tautology.

Both items are filed for operator review in the new HANDOFF
block landed alongside this document.
