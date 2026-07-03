# String-literal leak — design note

> **Evidence framing corrected 2026-07-03.** This design note
> originally cited `v2-babbleon-resilience-bench`'s 2026-06-21 run
> as measured evidence for the finding below. That run (and the
> 2026-06-22 layer-7 prototype run) were retracted in
> `crates/v2-babbleon-resilience-bench/CORRECTIONS.md`: every
> challenge's recovery target was a plain string literal that L2+L3
> don't touch by design, so a 100% crack rate measured the absence
> of literal-scrambling, not scramble strength — a tautology, not a
> finding about adversary capability. `CORRECTIONS.md` itself
> called amending this doc a required follow-up commit; that
> follow-up never landed until now. The design conclusion below
> does not depend on the retracted bench numbers — it follows from
> reading the preprocessor's own tokenizer logic, not from running
> an adversary against it — so the design stands; only the
> "bench proved this" framing is removed.

Reading the v2 preprocessor's own tokenizer settles this without
needing an adversary trial: L2 (keyword scramble) and L3
(whitespace-as-words) both treat an entire quoted string as one
atomic `Word` token and never descend into its contents (see
"Why this is true" below for the exact mechanism). Any secret a
program compares against a string literal — a password check, an
API key, a hash prefix, a magic flag name — therefore survives the
scramble byte-for-byte and is trivially readable in the scrambled
source.

This document records that structural finding, cross-references
the prior "layer 10" framing in `obfuscation-landscape.md`, and
proposes the next design step — a narrow string-literal
substitution mechanism scoped to operator-marked literals only.

## Why this is true

Four small challenge programs (`auth-literal-string`,
`auth-hash-check`, `state-machine`, `realistic-cli` — still present
under `crates/v2-babbleon-resilience-bench/challenges/`, each
carrying an in-file `# DEPRECATED` banner per `CORRECTIONS.md`,
since they remain useful as illustrations even though a crack rate
against them is not a measurement worth citing) make the point
concrete. Every one of these values is visible verbatim in the
scrambled source regardless of which of L2/L3/L4/L5/L6/L12 are
active, because none of those layers open a string literal's
contents — no adversary trial is needed to establish this; reading
the literal out of the scrambled file with a text editor works just
as well as an LLM subagent would. Each challenge's "secret" lives in
a string literal that L2 (keyword scramble) and L3
(whitespace-as-words) do not touch:

| challenge            | leak                                                     |
|----------------------|----------------------------------------------------------|
| auth-literal-string  | literal `"hunter2"` in `if x == "hunter2":` survives     |
| auth-hash-check      | literal `"00"` in `digest.startswith("00")` survives     |
| state-machine        | literal `"s0"`…`"accept"` + transition chars `"a"`…`"e"` |
| realistic-cli        | literal `"--insecure-skip-auth"` flag name survives      |

The subagents extracted these answers by reading the scrambled
bytes and pattern-matching for quoted substrings.  L3's
whitespace substitution does not break the visibility of
literals between quotes because the substitution leaves the
quote characters AND the literal body intact (the tokenizer
treats the entire `"hunter2"` run as one `Word` and never
descends into the literal's contents).

## How the prior planning treated this

`docs/v2/obfuscation-landscape.md` §3 "Data obfuscation" ›
"String obfuscation" (currently at line 192) addresses this
class explicitly:

> Split, XOR-encode, runtime-reconstruct.  Standard malware
> technique.
>
> **For Babbleon:** mostly NOT applicable.  Strings in user code
> are user data; obfuscating them changes program semantics from
> the user's perspective.
>
> **Exception:** path strings and URL strings that the v2
> preprocessor can rewrite at deployment time. [...]
>
> **Verdict: file as v2 layer 10, NARROWLY scoped to host-path
> strings only.**

The "user-data strings" reasoning is right for general-purpose
strings (log messages, user-facing text, format templates),
where mangling the content changes program semantics.  The
reasoning does NOT extend to strings whose content the program
treats as a secret: passwords, API keys, hash prefixes, magic
flag names.  Those ARE the threat-model material; user-side
"semantics preservation" is the wrong frame because the
*adversary* is the only consumer that wants to read the plain
form.

The bench-observed cells are exactly the "secret-strings"
sub-case.  The prior layer-10 framing covers them under the
"narrowly scoped" exception, but the scope today is "host-path
strings only" — too narrow for the bench's evidence.

## Proposed extension — operator-marked secret literals

The minimum-viable mechanism:

- The operator marks a literal as secret by wrapping it in a
  sentinel function call defined in a v2 helper module:

  ```python
  from babbleon.runtime import secret
  PASSWORD = secret("hunter2")
  ```

- The preprocessor recognises the `secret("...")` pattern, lifts
  the literal body out, and replaces it with a per-epoch
  compound + a reverse-lookup table the runtime resolves.

- At runtime the `babbleon.runtime.secret` function consults the
  table to recover the plaintext (analogous to the wrapper-table
  lookup the launcher does for identifier compounds).

This is **opt-in per literal**.  Reasoning:

- **Avoids the user-data problem.**  Log strings, format
  templates, exception messages don't get scrambled because the
  operator didn't mark them.  Program semantics are
  byte-identical for unmarked literals.
- **No tokenizer-correctness blocker.**  Recognising a
  syntactically-narrow `secret("...")` call is far easier than
  recognising arbitrary Python string literals in the general
  case (which is HANDOFF item 7's real-tokenizer blocker).  A
  string-matching pre-pass over the source text catches the
  common shape; full Python parsing is the production path but
  is not gating.
- **Operator-auditable.**  `git grep 'secret('` enumerates every
  scrambled literal.  No hidden state.

The mechanism composes with L2 and L3:

```
ops:  source
        v
        layer 7 (this) — replace secret("…") with secret("<compound>")
        v
        layer 2        — replace keywords with compounds
        v
        layer 3        — replace whitespace with compounds
        v
        bytes on disk
```

Inverse on unscramble runs the passes in reverse.

## Naming and numbering

`obfuscation-landscape.md` already used "layer 10" for narrow
host-path string substitution.  The bench-found scope is
broader (any operator-marked literal), so this is a different
mechanism.  Two options:

- **Rename layer 10 to "string-literal substitution (operator-
  marked + path strings)"** and roll both scopes into one
  layer.  Cleaner; one mechanism handles both cases.
- **File as "layer 11"** and keep layer 10's narrow scope.
  Honest to the original framing but produces overlapping
  layers.

**Recommendation:** rename layer 10.  The mechanism is the
same: a marker, a wordlist compound, a runtime lookup.  The
"path strings vs operator-marked" distinction is a policy
parameter, not a different design.

## What this does NOT close

- **String literals the operator forgot to mark.**  The
  mechanism is opt-in; an unmarked secret leaks.  Mitigation:
  a lint pass that flags literals containing entropy markers
  (high-Shannon hex, base64-shaped strings, paths under
  `/etc/`) and recommends wrapping.  Not in MVP.
- **Computed secrets** that are reconstructed at runtime from
  unmarked pieces.  Example: `auth(x): return x == chr(104) +
  chr(117) + chr(110) + chr(116) + chr(101) + chr(114) + "2"`.
  Recovering the literal requires evaluating the construction —
  trivial for any adversary with code-execution access (an LLM
  subagent with a `python3` tool just pipes the `chr()`
  construction through it and reads off the result; this is a
  first-principles capability claim, not something that needs a
  bench trial to establish). Sandbox-equipped adversaries defeat
  the "no literals" defence by execution, not by literal search —
  see `docs/v2/sandbox-execution-defence.md` for the full threat
  model and candidate countermeasures. A separate layer (decoy
  injection, chunk reorder, or *sandbox-resistant runtime
  construction*) is needed to address this; layer 7 alone is
  insufficient even with the marker discipline.
- **f-strings** (`f"prefix-{secret}-suffix"`).  The recognised
  pattern would need extension; today's `secret("...")`
  proposal handles only direct string literals.

## Acceptance criteria for the layer-7 prototype

When the layer lands, re-run the bench at N=3-5 per cell against
the 4 existing challenges PLUS a new `computed-secret` challenge.
The pass criterion:

- Cells where the secret lives in an operator-marked literal:
  crack fraction `<10%`.
- Cells where the secret lives in an unmarked literal (the
  current 4 seed challenges as-is): crack fraction unchanged
  (this is the negative control proving the mechanism is opt-in).

If the L2+L3+L7 combination still cracks at >10% on the marked-
literal cells, the next escalation is layer 4 (chunk reorder) +
layer 5 (decoy injection).  The decision tree is now data-driven
end to end.

## Implementation sequence

1. **Recognise `secret("...")` in the MVP tokenizer.**  Special-
   case scanner pass before tokenization; emit a
   `Token::SecretLiteral(body)` variant alongside the existing
   `Word` / `Whitespace` variants.  ~50 LOC.
2. **Per-epoch secret-literal wordlist.**  Mirror the existing
   keyword and whitespace wordlist constructors.  ~120 LOC +
   tests.
3. **`scramble_secret_literals` / `unscramble_secret_literals`
   passes.**  Mirror layer-2 keyword scrambler.  ~80 LOC +
   tests.
4. **`babbleon.runtime.secret` Python helper module.**  Reads
   the per-epoch table from the daemon over the same socket
   protocol as keyword compounds; returns the plaintext.
   ~40 LOC + tests.
5. **Daemon-protocol extension.**
   `Request::GetSecretLiteralTable`.  Mirror
   `GetWhitespaceCompounds` exactly.  ~60 LOC + tests.
6. **Add `LayerConfig::layer7_secret_literal_substitution` bool
   to the bench.**  Re-run.

Wall-clock estimate: 1-2 sessions to working prototype, 1
session for the bench re-run.

## Cross-references

- `crates/v2-babbleon-resilience-bench/runs/2026-06-21-claude-opus-4-7-subagent/README.md`
  — the retracted run that originally prompted this design note
  (see the `INVALIDATED.md` stub in the same directory and
  `crates/v2-babbleon-resilience-bench/CORRECTIONS.md` for why).
- `docs/v2/obfuscation-landscape.md` §3 "Data obfuscation"
  — prior framing this doc supersedes (for the secret-strings
  sub-case).
- `docs/v2/structure-scrambling.md` — the existing 5-layer
  composition story this layer joins.
- HANDOFF.md 2026-06-21 night session block — operator-facing
  summary of the (now-retracted) bench run; see
  `CORRECTIONS.md` for the retraction.
- HANDOFF item 7 — "real Python tokenizer" swap.  This layer is
  designed to NOT block on item 7 by using a narrow opt-in
  marker recognisable to the MVP tokenizer.
