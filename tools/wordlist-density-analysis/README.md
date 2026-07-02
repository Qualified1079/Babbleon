# tools/wordlist-density-analysis

Score every entry in the Babbleon baseline wordlist by BPE token
count under `cl100k_base` and `o200k_base`, then optionally emit a
filtered subset that keeps only entries in a given token-count band.

## Why this exists

`TODO.md` § "Benchmarks + measurements" and `HANDOFF.md` 2026-06-27
priority 4 both name a **wordlist post-filter by tokenization
density** as the next measurable follow-on to the variable-alias-
count regime that landed in the 2026-06-27 session.  Hypothesis: a
subset of the corpus that skips both the trivially-tokenizable
common-English words (`hello` — 1 cl100k token) and the absurdly-
rare six-plus-token entries (`zyzzyva` — 8 cl100k tokens) will
raise the attention cost of the scrambler without shrinking the
identifier pool below the role budget in
`docs/v2/phase0-research-notes.md` §11.

This tool is the **analysis** for that decision.  Wiring a filtered
wordlist into `v2-babbleon-core::wordlist` is a separate change
gated on the adversarial-LLM re-test producing a baseline number
(HANDOFF 2026-06-27 priority 1).

## Standalone workspace

Same pattern as `tools/tokenizer-benchmark/`: this crate is its own
workspace so `tiktoken-rs` and its embedded BPE tables stay out of
the default Babbleon workspace build.  Follow the sibling tool's
convention if adding another tokenizer-shaped analysis tool.

## Usage

Score every word and print summary + histograms:

```
cd tools/wordlist-density-analysis
cargo run --release -- \
  --wordlist ../../crates/babbleon/wordlist/words.txt
```

Score every word and dump a per-word CSV:

```
cargo run --release -- \
  --wordlist ../../crates/babbleon/wordlist/words.txt \
  --scores-out scores.csv
```

Emit a filtered wordlist using absolute token cutoffs (recommended
for the Babbleon baseline because the token-count distribution is
peaked — see `RESULTS.md`):

```
cargo run --release -- \
  --wordlist ../../crates/babbleon/wordlist/words.txt \
  --filter cl100k \
  --min-tokens 3 --max-tokens 5 \
  --filtered-out filtered.txt \
  --manifest-out filtered.manifest
```

Percentile cutoffs work too, but note they collapse to only a few
discrete values on this distribution:

```
cargo run --release -- \
  --wordlist ../../crates/babbleon/wordlist/words.txt \
  --filter cl100k \
  --min-percentile 33 --max-percentile 97 \
  --filtered-out filtered.txt \
  --manifest-out filtered.manifest
```

Mixing is allowed: `--min-percentile 33 --max-tokens 5` binds low
to the 33rd percentile and high to a literal cutoff of 5 tokens.

Apply the same band under **both** tokenizers and keep only the
intersection:

```
cargo run --release -- \
  --wordlist ../../crates/babbleon/wordlist/words.txt \
  --filter cl100k \
  --min-tokens 3 --max-tokens 5 \
  --intersect-tokenizers \
  --filtered-out filtered-both.txt \
  --manifest-out filtered-both.manifest
```

Intersection produces a stricter subset (words must be well-
behaved under both cl100k and o200k) at the cost of shrinking the
kept-count.  See `RESULTS.md` for the tradeoff table.

## Module layout

Compartmentalized so a break in one module is targeted:

- `load` — read + validate the wordlist (`[a-z]+`, unique, non-empty).
- `score` — tokenizer wrapper + per-word `WordScore` emission.
- `stats` — sorted `Distribution` with nearest-rank percentiles +
  bucketed histogram.
- `filter` — `Bound { Percentile(f64), Tokens(usize) }` +
  `FilterSpec` + `FilterResult` with resolved cutoffs and drop
  counts.
- `report` — stdout summary + CSV + manifest emitters.
- `main` — CLI orchestration only.

Each module carries its own `#[cfg(test)]` block; run
`cargo test --release` from this directory.

## Determinism

Scoring is deterministic: same wordlist + same `tiktoken-rs`
version → same CSV bit-for-bit.  No RNG anywhere in this tool.
The filter is likewise deterministic and preserves the input order
of the wordlist in its emitted file.

## What this tool does NOT do

- It does not wire the filtered wordlist into the Babbleon runtime.
  See `crates/v2-babbleon-core/src/wordlist.rs` for the load
  surface a follow-up change would edit.
- It does not run the adversarial-LLM measurement.  See
  `crates/v2-babbleon-resilience-bench/` for that.
- It does not tokenize *compounds* (multi-word Babbleon aliases).
  See `tools/tokenizer-benchmark/` for that.
