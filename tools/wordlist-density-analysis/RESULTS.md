# Results — wordlist-density-analysis

Runs against `crates/babbleon/wordlist/words.txt` (369 652 entries,
lowercase ASCII, unique) using `tiktoken-rs 0.5.9` on the branch tip
of `claude/magical-turing-mele8c` at commit `3fbafab`
(2026-07-02, machine: session sandbox).

## Full scoring pass

```
Loaded 369 652 words.

cl100k_base:   mean=2.987  median=3  min=1  max=13
o200k_base:    mean=2.890  median=3  min=1  max=13
```

Percentile → token count cutoff (nearest-rank):

|  pctile | cl100k | o200k |
|--------:|-------:|------:|
|     1.0 |      1 |     1 |
|     5.0 |      2 |     2 |
|    10.0 |      2 |     2 |
|    25.0 |      2 |     2 |
|    50.0 |      3 |     3 |
|    75.0 |      4 |     3 |
|    90.0 |      4 |     4 |
|    95.0 |      5 |     4 |
|    99.0 |      6 |     5 |

Histogram (tokens per word):

```
cl100k                     o200k
 1      6844  (  1.85%)     1      7841  (  2.12%)
 2    113269  ( 30.64%)     2    125389  ( 33.92%)
 3    156788  ( 42.42%)     3    157163  ( 42.52%)
 4     69098  ( 18.69%)     4     61694  ( 16.69%)
 5     18918  (  5.12%)     5     14619  (  3.95%)
 6      3883  (  1.05%)     6      2458  (  0.66%)
 7       707  (  0.19%)     7       389  (  0.11%)
 8       117  (  0.03%)     8        84  (  0.02%)
 9        23  (  0.01%)     9        11  (  0.00%)
10         3  (  0.00%)    10         2  (  0.00%)
>10        2  (  0.00%)   >10         2  (  0.00%)
```

### Full-pass timing

~1.7 s wall-clock on the session sandbox (release build, no
parallelism, single scoring pass over 369 652 entries under both
tokenizers).  Cheap enough to re-run whenever the wordlist changes.

## Filter matrix — absolute token cutoffs

Every value below is the number of entries that survive a filter
with `--min-tokens L --max-tokens H`.  "Intersect" rows require
the word to pass the same `[L, H]` band under **both** cl100k and
o200k (via `--intersect-tokenizers`).

| tokenizer   | [L, H] | kept    | kept % of 369 652 |
|-------------|--------|--------:|------------------:|
| cl100k      | [3, 4] | 225 886 |            61.1 % |
| cl100k      | [3, 5] | 244 804 |            66.2 % |
| cl100k      | [4, 4] |  69 098 |            18.7 % |
| cl100k      | [4, 5] |  88 016 |            23.8 % |
| o200k       | [3, 4] | 218 857 |            59.2 % |
| o200k       | [3, 5] | 233 476 |            63.2 % |
| o200k       | [4, 4] |  61 694 |            16.7 % |
| o200k       | [4, 5] |  76 313 |            20.6 % |
| **intersect** | [3, 4] | 202 139 |            54.7 % |
| **intersect** | [3, 5] | 223 009 |            60.3 % |
| **intersect** | [4, 4] |  46 523 |            12.6 % |
| **intersect** | [4, 5] |  66 264 |            17.9 % |

## Cross-reference: wordlist invariants

`crates/babbleon/wordlist/README.md` names three invariants any
wordlist (including a filter output) must uphold.  For the
`intersect [3, 5]` candidate (223 009 entries):

- **Invariant 1 (`^[a-z]+$`)** — preserved by construction; the
  filter output is a subset of the baseline, which already
  satisfies invariant 1.  The tool's `load` module also enforces
  the same check so any filtered wordlist would be rejected by the
  runtime loader if it drifted.
- **Invariant 2 (≥ 200k safety margin)** — the wordlist README
  cites 200 000 as the lower safety bound.  Bands crossing that
  line under either single-tokenizer or intersection mode:

  | Filter                     | Kept    | ≥ 200 k safety? |
  |----------------------------|--------:|:---------------:|
  | cl100k [3, 4]             | 225 886 | ✓ |
  | cl100k [3, 5]             | 244 804 | ✓ |
  | cl100k [4, 4]             |  69 098 | ✗ |
  | cl100k [4, 5]             |  88 016 | ✗ |
  | o200k [3, 4]              | 218 857 | ✓ |
  | o200k [3, 5]              | 233 476 | ✓ |
  | o200k [4, 4]              |  61 694 | ✗ |
  | o200k [4, 5]              |  76 313 | ✗ |
  | intersect [3, 4]          | 202 139 | ✓ (barely) |
  | intersect [3, 5]          | 223 009 | ✓ |
  | intersect [4, 4]          |  46 523 | ✗ |
  | intersect [4, 5]          |  66 264 | ✗ |

  Every `[3, H]` band clears the safety margin; every `[4, H]`
  band busts it and would need to be paired with a multilingual
  wordlist expansion before shipping.
- **Invariant 3 (tokenization cost roughly uniform)** — this is
  what the filter deliberately *tunes*.  Post-filter compound-cost
  numbers replace the pre-filter ones in `tokenizer-benchmark/`
  RESULTS.md; the compound-to-spaced ratio (~1.07×) remains
  unchanged, matching the invariant's phrasing about "distribution
  looking like natural English words".

## Findings

### 1. The distribution is peaked, not tail-heavy.

Under both tokenizers, ~76 % of the corpus sits in the 2–3 token
band (cl100k: 30.64 + 42.42 = 73.06 %; o200k: 33.92 + 42.52 =
76.44 %).  This is expected — the wordlist is `dwyl/english-words`,
which is dominated by common English shapes that BPE merges
efficiently — but it changes what "mid-tail filter" means in
practice.

### 2. Percentile-based filters collapse to a few discrete cutoffs.

A percentile band `[30, 70]` on cl100k resolves to token cutoffs
`[2, 4]` — because the 30th and 25th percentiles both land on 2,
and the 70th sits on 4.  That keeps 339 155 / 369 652 = 91.75 %
of the corpus.  Almost the whole list.  A "mid-tail" percentile
intuition borrowed from long-tailed distributions overstates the
selectivity you get on this one.

**Consequence:** operators wanting a stricter mid-tail on the
Babbleon baseline should use absolute token cutoffs
(`--min-tokens 3 --max-tokens 5`) rather than percentile bands.
The tool supports both and lets them mix if it helps
(`--min-percentile 33 --max-tokens 5` is fine).

### 3. Recommendation for the follow-up wiring session.

The role budget in `docs/v2/phase0-research-notes.md` §11 puts the
identifier role at ~370 k (largest need).  Adjacent roles (decoy,
direction marker, whitespace, keyword-per-language, prompt-
injection) sum to another ~135 k, for ~505 k across all roles.
Multi-language wordlists (TODO.md phase 4, HermitDave/FrequencyWords)
would compound the corpus size, so the identifier role can afford
a tighter mid-tail filter than the current 370 k baseline suggests.

Plausible starting points for the follow-up:

- **cl100k [3, 5]** (244 804 kept, 66.2 %) — drops the 6 844 one-
  token trivially-tokenizable entries plus the 23 650 rare 6+-
  token entries; leaves a healthy pool for the identifier role
  once multilingual wordlists compound.
- **cl100k [3, 4]** (225 886 kept, 61.1 %) — stricter; drops the
  5-token tail as well.  Still enough for the identifier role
  in a two-language configuration.

Either of these is a **hypothesis to test**, not a mandate to ship.
The adversarial-LLM re-test filed as HANDOFF priority 1 must run
against both the baseline and at least one filtered wordlist before
we can attribute a crack-rate delta to the density filter rather
than to noise.

## Compound-cost delta vs baseline

The Babbleon scrambler emits N-word compounds, not individual
words, so the load-bearing metric is compound token cost, not
per-word cost.  Feeding each filter output into
`tools/tokenizer-benchmark/ --compound-n 4 --samples 2000` gives
the direct decision-support number for the go/no-go on the wiring
change.

Mean tokens per 4-word compound, averaged over three seeds
(`--seed {1,2,3}`, 2000 samples each), against the same seeds' runs
on the baseline wordlist:

|                        Wordlist |  cl100k mean |    Δ cl100k |   o200k mean |    Δ o200k |
|--------------------------------:|-------------:|------------:|-------------:|-----------:|
|              Baseline (369 652) |        11.96 |           — |        11.53 |          — |
|        cl100k [3, 4] (225 886) |        13.11 |     +9.6 %  |        12.55 |    +8.8 %  |
|        cl100k [3, 5] (244 804) |        13.60 |    +13.7 %  |        12.97 |   +12.5 %  |
|         o200k [3, 4] (218 857) |        13.36 |    +11.7 %  |        13.01 |   +12.8 %  |
|         o200k [3, 5] (233 476) |        13.74 |    +14.9 %  |        13.38 |   +16.0 %  |
|    **intersect [3, 5]** (223 009) |    **13.80** | **+15.4 %** |    **13.38** | **+16.1 %** |

The intersection row is the clear winner if the operator wants
one filter that raises compound cost under **both** tokenizers.
`cl100k [3, 5]` beats `intersect [3, 5]` on kept-count by 21 795
entries but underperforms it on o200k compound cost (+12.5 %
vs +16.1 %).  `o200k [3, 5]` matches the intersection on o200k
compound cost but underperforms on cl100k (+14.9 % vs +15.4 %).
The intersection filter costs 21 795 kept entries (~8.9 %
relative shrinkage vs `cl100k [3, 5]`) and buys +2.7 pp of o200k
compound cost improvement plus +1.7 pp of cl100k compound cost
improvement.

Ratios of compound to spaced-baseline token count are unchanged
(~1.07× under both tokenizers across every filter and the baseline).
The absolute compound token cost went up because the filter drops
the trivially-tokenizable one-token entries and the merge-happy
short entries, but the *no-whitespace penalty* is a separate signal
that the filter does not touch.

Per-seed spread on `cl100k [3, 5]` (cl100k tokenizer):

| seed | cl100k mean |
|-----:|------------:|
|    1 |       13.63 |
|    2 |       13.59 |
|    3 |       13.58 |

Standard deviation across three seeds is ~0.02 tokens — the delta
vs baseline is roughly two orders of magnitude larger than run-to-
run noise at this sample count.

### What this measurement is and is not

**Is:** a stable, reproducible number for how much more expensive
each 4-word compound becomes under a given filter.  Anchors the
"is the filter worth wiring?" question in wall-clock attacker cost.

**Is not:** a measure of adversarial-LLM crack rate.  The
adversarial re-test filed as HANDOFF priority 1 is what tells us
whether that +13.7 % token cost actually moves a model's ability
to reason through the scramble.  A filter that raises attention
cost without moving crack rate is theatre; a filter that moves
crack rate at low cost is a ship candidate.  The two must be
reported together.

## Reproducing these numbers

```
cd tools/wordlist-density-analysis
cargo build --release
./target/release/wordlist-density-analysis \
  --wordlist ../../crates/babbleon/wordlist/words.txt
```

Same tiktoken-rs version + same wordlist file → same numbers
bit-for-bit.
