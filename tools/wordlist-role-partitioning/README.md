# tools/wordlist-role-partitioning

Compute per-role wordlist pool sizes for the Babbleon v2 obfuscator
under a chosen attacker model + wordlist.  Answers the executable
form of HANDOFF 2026-07-02 refreshed next-session priority 5:

> **Wordlist role-partitioning formula.**  A formula
> `N_role = f(rotation_hz, work_factor, compound_n)` would let the
> density filter and the role budget be tuned jointly rather than by
> back-of-envelope.

## What the tool does

Given

- a **wordlist model** (baseline or `intersect[3, 5]` filter output),
- an **attacker model** (events per epoch, target lifetime
  collision probability, secret lifetime in epochs), and
- a **role table** (six-role provisional table from
  `docs/v2/phase0-research-notes.md` §11),

produce one row per role showing

- required pool size (words),
- target vs achieved entropy in bits,
- attention-cost multiplier vs the wordlist's baseline compound
  cost, and
- birthday-bound collision probability per epoch + per lifetime,

plus a **fit-in-wordlist** verdict (FITS / OVERFLOW) with the
utilization percentage and headroom in words.

## Why this exists

The phase0-research-notes §11 "provisional pool allocations" table
was pinned by back-of-envelope reasoning ("the identifier compound
space is well above the information-theoretic minimum").  Now that
`tools/wordlist-density-analysis/RESULTS.md` gives concrete
alternatives (baseline 369 652, `intersect[3, 5]` 223 009 words), the
next question is: **which of those wordlists survive the role
allocation under a formal entropy target?**  This tool is the
executable formalisation.

## Two entropy models per role

Not every role has the same collision profile.  The tool exposes
both:

- **Birthday** — `target = 2·log2(events) + collision_margin +
  log2(lifetime)`.  Correct for **compound_n ≥ 2** roles where the
  attacker sees compounds as (near-)random observations of a large
  space.  The identifier / decoy / direction_marker roles use this.
- **Uniqueness** — `target = log2(events × alias_count × safety)`.
  Correct for **compound_n = 1** roles (keyword) and for
  permutation-driven layers (L3 whitespace) where the scrambler
  produces a *bijective* mapping; accidental within-mapping
  collisions are impossible by construction and the pool just
  needs to fit the bijection.  The whitespace / keyword /
  prompt_injection roles use this.

The provisional-v2 table splits the six roles across the two models
by matching each role's L2/L3 layer semantics.

## Presets and knobs

Wordlist presets (`--wordlist`):

- `cl100k-baseline` (default) — 369 652 entries, 11.96 tokens per
  compound at compound_n=4.  Matches
  `crates/babbleon/wordlist/words.txt`.
- `cl100k-intersect35` — 223 009 entries, 13.80 tokens/compound.
  Output of `tools/wordlist-density-analysis/` with `--filter
  cl100k --min-tokens 3 --max-tokens 5 --intersect-tokenizers`.

Attacker presets:

- default (developer-laptop): 2 000 events/epoch, 1e-6 target
  lifetime collision, 8 760-epoch (1-year) lifetime.  Calibrated
  for an obfuscation layer that is not the last line of defense.
- `--paranoid`: same events + lifetime, 1e-12 target.  Under this
  posture the provisional table's aggregate pool exceeds the
  baseline; the tool prints OVERFLOW so the operator sees the
  strict tradeoff.

Individual overrides (`--events-per-epoch`, `--collision-probability`,
`--lifetime-epochs`, `--wordlist-size`, `--wordlist-mean-tokens`) let
you drive an arbitrary attacker or hypothetical wordlist.

## Usage

Default text report on stdout:

```
cd tools/wordlist-role-partitioning
cargo run --release
```

Under `intersect[3, 5]` filter:

```
cargo run --release -- --wordlist cl100k-intersect35
```

Under the paranoid preset (shows OVERFLOW):

```
cargo run --release -- --paranoid
```

Emit a markdown fragment suitable for dropping into `docs/v2/`
alongside the text summary:

```
cargo run --release -- --report-out RESULTS.md
```

## Module layout

Compartmentalized so a break in one module is targeted (same
discipline as `tools/wordlist-density-analysis/`):

- `entropy` — pure-math primitives (`compound_entropy_bits`,
  `required_pool_size`, `birthday_collision_probability`,
  `attention_cost_multiplier`).
- `params` — `Role`, `AttackerModel`, `WordlistModel`, plus
  `EntropyModel` and the six-role `Role::provisional_v2_table()`.
- `allocation` — `AllocationTable::compute(roles, attacker,
  wordlist) -> AllocationTable`; carries the fit verdict and
  headroom.
- `report` — `render_text` + `render_markdown`.
- `main` — CLI orchestration only.

Each module carries its own `#[cfg(test)]` block; run
`cargo test --release` from this directory.

## What this tool does NOT do

- It does not edit `crates/v2-babbleon-core/src/wordlist.rs`.
  Wiring per-role subsets into the runtime is a separate diff
  gated on adversarial-LLM measurement (HANDOFF 2026-07-02
  priority 1).
- It does not tokenize compounds — it consumes the mean
  tokens/compound number that `tools/tokenizer-benchmark/`
  produced.
- It does not filter or score the wordlist itself — that is
  `tools/wordlist-density-analysis/`'s job.
- It does not commit to a single "correct" entropy model.  The
  Birthday-vs-Uniqueness choice per role is a design position the
  operator can revisit by editing `Role::provisional_v2_table()`.

## Standalone workspace

Same pattern as `tools/wordlist-density-analysis/` and
`tools/tokenizer-benchmark/`.  This crate is its own workspace so
`clap`'s procedural macros stay out of the default Babbleon
workspace build.  Follow the sibling tools' convention if adding
another analysis tool.

## Cross-references

- `docs/v2/phase0-research-notes.md` §11 (the provisional table
  this tool formalizes).
- `tools/wordlist-density-analysis/RESULTS.md` (source of the
  `intersect[3, 5]` numbers used as a wordlist preset).
- `crates/v2-babbleon-preprocessor/src/identifier_scrambler.rs`
  (`ALIAS_COUNT`, `MIN_ALIAS_COUNT`, `MAX_ALIAS_COUNT` — the
  alias-count knobs feeding `Role.alias_count`).
