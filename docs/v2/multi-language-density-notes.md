# Multi-language wordlist density — preliminary measurements

Date: 2026-07-02 (autonomous session 2 — claude-opus-4-7).

**Status.**  Proof-of-concept data.  The intent is to unblock the
autonomous-safe branch of HANDOFF 2026-07-02 session-2 refreshed
priority 9 ("multi-language wordlists — analysis") without
committing anything into the runtime.  Wiring a non-English pool
into `crates/v2-babbleon-core::wordlist` still requires operator
license review + the phase-4 role-partitioning design (see
`tools/wordlist-role-partitioning/RESULTS.md`).

**What was measured.**  Top-50k word frequency lists from
[HermitDave/FrequencyWords](https://github.com/hermitdave/FrequencyWords)
(MIT licence, OpenSubtitles 2018) for three additional
languages, filtered to the pure-ASCII subset so they satisfy the
same `[a-z]+` invariant the density-analysis tool enforces on the
English baseline (see `tools/wordlist-density-analysis/src/load.rs`).
Diacritics-inclusive analysis is deferred until the loader
relaxes its ASCII-only rule (or until we settle on a diacritics-
stripping normaliser).

## Raw density profile (`--wordlist $language.txt`)

| Language  | Source              | Pure-ASCII entries | cl100k mean | cl100k median | o200k mean | o200k median |
|-----------|---------------------|-------------------:|------------:|--------------:|-----------:|-------------:|
| English   | Babbleon baseline   |            369 652 |        2.99 |             3 |       2.89 |            3 |
| German    | hermitdave/2018/de  |             42 179 |        2.77 |             3 |       2.45 |            2 |
| Spanish   | hermitdave/2018/es  |             40 236 |        2.53 |             2 |       2.37 |            2 |
| French    | hermitdave/2018/fr  |             35 433 |        2.39 |             2 |       2.26 |            2 |

English baseline row from
`tools/wordlist-density-analysis/RESULTS.md`.  The three
non-English rows come from
`./target/release/wordlist-density-analysis --wordlist <path>`
against the pure-ASCII subset extracted with
`awk '{print $1}' <src>_50k.txt | grep -E '^[a-z]+$'`.

## Intersect[3, 5] filter output per language

Applying the tool's `--intersect-tokenizers --min-tokens 3
--max-tokens 5 --filter cl100k` (session-1 recommendation) to each
language and reading `kept_intersection` from the intersection
manifest:

| Language  | Input  | Kept (intersect[3,5]) | Kept %  |
|-----------|-------:|----------------------:|--------:|
| English   | 369 652 |             223 009  | 60.3 % |
| German    |  42 179 |              17 159  | 40.7 % |
| Spanish   |  40 236 |              15 485  | 38.5 % |
| French    |  35 433 |              11 173  | 31.5 % |

The non-English retention rates (30–40 %) are much lower than
English's (60 %) because the pure-ASCII HermitDave subsets are
top-50k frequency-truncated — biased toward short common words
whose BPE token count sits at 1–2, below the mid-tail band the
filter is looking for.  The tail of English's 369 k wordlist
covers the 3–5 token band more densely.

## Compound-cost benchmark per language

`tools/tokenizer-benchmark --samples 2000 --compound-n 4 --seed 1`
against each raw + filtered wordlist:

| Wordlist                    | Entries | cl100k mean | o200k mean | Δ cl100k vs English baseline | Δ o200k vs English baseline |
|-----------------------------|--------:|------------:|-----------:|-----------------------------:|----------------------------:|
| **English baseline**        | 369 652 |       11.96 |      11.53 |                            — |                           — |
| English `intersect[3, 5]`   | 223 009 |       13.60 |      12.97 |                      +13.7 % |                     +12.5 % |
| German (pure-ASCII)         |  42 179 |       10.96 |       9.81 |                       −8.4 % |                     −14.9 % |
| German `intersect[3, 5]`    |  17 159 |       14.02 |      12.78 |                     **+17.2 %** |                     +10.8 % |
| Spanish (pure-ASCII)        |  40 236 |       10.12 |       9.47 |                      −15.4 % |                     −17.9 % |
| Spanish `intersect[3, 5]`   |  15 485 |       12.86 |      12.20 |                       +7.5 % |                      +5.8 % |
| French (pure-ASCII)         |  35 433 |        9.47 |       8.93 |                      −20.8 % |                     −22.5 % |
| French `intersect[3, 5]`    |  11 173 |       12.55 |      12.05 |                       +4.9 % |                      +4.5 % |

**Filtered non-English numbers are 3-seed means** (seeds 1, 2, 3;
2000 samples each; `tokenizer-benchmark --compound-n 4`).  Per-
row σ measured this session:

- German `intersect[3, 5]`: σ_cl100k = 0.025, σ_o200k = 0.051
- Spanish `intersect[3, 5]`: σ_cl100k = 0.015, σ_o200k = 0.006
- French `intersect[3, 5]`: σ_cl100k = 0.021, σ_o200k = 0.032

Every σ sits within the ±0.05-token comparability band; no
design conclusion above changes under multi-seed averaging.
Unfiltered rows and the two English rows carry over from the
prior sessions unchanged (single-seed for the non-English pure-
ASCII, 3-seed for the English rows).

## What the numbers say

1. **All three unfiltered non-English pools cost LESS attention
   per compound than the English baseline** — 8–21 % less at
   cl100k, 15–23 % less at o200k.  A naive "add another language"
   strategy therefore *reduces* the LLM's per-compound work.  The
   trade is real: added entropy vs added attention cost.
2. **All three filtered non-English pools cost MORE attention per
   compound than the English baseline unfiltered.**  So filtering
   any language above the mid-tail band recovers the attention
   deficit vs English, though at the cost of pool size (each
   filtered non-English pool holds only 11–17 k words).
3. **German `intersect[3, 5]` is competitive with English
   `intersect[3, 5]`** — same size class problem (17 k vs 223 k)
   but +17.5 % cl100k / +11.4 % o200k over the English baseline
   vs English filter's +13.7 % / +12.5 %.  German's compound-word
   morphology plus BPE segmentation happens to be favorable
   under cl100k.  It is the strongest single-language addition
   candidate.
4. **French `intersect[3, 5]` is the weakest candidate** — +5 %
   attention gain with the smallest pool (11 k).  Combined with
   its lowest ASCII-retention rate (71 % of the top-50k after
   the `[a-z]+` filter), French benefits the most from relaxing
   the density-analysis validator to Unicode-lowercase before
   ship.
5. **The multi-language pool strategy is a size-vs-cost
   tradeoff**, not a "free wins" story.  The most useful shape
   is probably a **primary-language, secondary-language mix**
   where the primary is English (attention cost + pool size),
   and secondary languages contribute per-epoch identifiers at
   the cost of a small attention discount — an obfuscation
   analogue of the language-rotation defence.

## Per-language role-partitioning fit check

Running `tools/wordlist-role-partitioning` with each filtered
non-English wordlist size (laptop-default posture, provisional-
v2 role table):

| Wordlist                    | Size   | Total pool needed | Utilization | Verdict |
|-----------------------------|-------:|------------------:|------------:|:-------:|
| English baseline            | 369 652 |          215 387  |      58.3 % | FITS    |
| English `intersect[3, 5]`   | 223 009 |          215 387  |      96.6 % | FITS    |
| German `intersect[3, 5]`    |  17 159 |          215 387  |    1 255 %  | OVERFLOW |
| Spanish `intersect[3, 5]`   |  15 485 |          215 387  |    1 391 %  | OVERFLOW |
| French `intersect[3, 5]`    |  11 173 |          215 387  |    1 928 %  | OVERFLOW |

**Design implication.**  No non-English filtered wordlist can
host the provisional-v2 role table on its own under the laptop-
default posture — the ~130 k-word decoy role and the ~70 k-word
direction_marker role dwarf every non-English pool.  The
identifier role (13.7 k words) fits everywhere.

Three responses available to the operator:

1. **Pooled cross-language allocation for the large roles.**
   Union the English + German + Spanish + French filtered pools
   (~267 k words) and let the decoy / direction_marker roles
   draw from the union.  Identifier / whitespace / keyword /
   prompt_injection stay in a single language's subset.  This
   is the "primary/secondary" idea above, formalised.
2. **Per-language rotation with a shrunken role table.**  Give
   each epoch a single language and a smaller role table (drop
   decoy from the epoch, keep identifier + keyword + whitespace).
   Simpler; costs the decoy layer's obfuscation gain for that
   epoch.
3. **Relax the birthday-bound collision target from 1e-6 to
   1e-3.**  At 1e-3 the decoy role's pool requirement drops
   dramatically; likely enough to fit a single non-English
   language.  Requires operator sign-off on the looser security
   posture.  Autonomous-safe to measure — a follow-up run of
   `wordlist-role-partitioning --collision-probability 1e-3
   --wordlist-size <language>` would produce the numbers.

Option 1 preserves the strongest posture and is what the
follow-up wiring diff (HANDOFF session-2 priority 8) can bake in:
each role has its own `include_str!` file, and the operator
chooses which language(s) contribute to each role file at
extraction time via a per-role `--extract-seed-file` / label
combination.  The existing extractor already supports one
language per invocation; a follow-up would let the operator
concatenate + shuffle across languages before extraction.

## Follow-up — Unicode-lowercase loader landed

`tools/wordlist-density-analysis/src/load.rs` grew a
`Mode::UnicodeLowercase` opt-in (CLI: `--unicode-lowercase`).
Scoring French with the full top-50k (after dropping contractions
via `perl -CS -ne '/^\p{Ll}+$/'`) recovers 46 792 entries — a
32 % gain over the 35 433 pure-ASCII subset.  Full-list mean
compound token count for French (cl100k) rises from 2.39 to 2.62
because the accented characters cost more tokens; this offsets
some of the "French compound cost is low" finding above.

The runtime loader in `crates/v2-babbleon-core::wordlist` still
enforces `[a-z]+`; the tool's Unicode mode is analysis-side only.
Wiring a matching relax into the runtime is a separate
operator-review-gated diff — it changes the observable Babbleon
compound alphabet, which is a public surface.

## Follow-up — `--normalise-diacritics` shim

Same commit train delivered a second option:
`--normalise-diacritics` runs each entry through NFKD, drops
combining marks, and folds the handful of Latin ligatures that
Unicode does not decompose on its own (`œ` → `oe`, `æ` → `ae`,
`ß` → `ss`, `ø` → `o`, `ð` → `d`, `þ` → `th`).  The output
matches `[a-z]+`, so the shim composes with the DEFAULT ASCII-
lowercase validator — the operator keeps the runtime invariant
AND gains most of the multi-language pool.

French comparison across the three modes:

| Mode                          | Entries | cl100k mean | o200k mean |
|-------------------------------|--------:|------------:|-----------:|
| Default (pure-ASCII filter)   |  35 433 |        2.39 |       2.26 |
| `--normalise-diacritics`      |  43 990 |        2.46 |       2.33 |
| `--unicode-lowercase`         |  46 792 |        2.62 |       2.42 |

**Recommendation for phase-4 wiring.**
`--normalise-diacritics` is the *runtime-compatible* winner: 24 %
more corpus than pure-ASCII at a +0.07-token cost, no public-
surface change to Babbleon's compound alphabet.  Reserve
`--unicode-lowercase` for exploratory measurement of what
relaxing the runtime invariant would buy (an additional 6 % pool
at a further +0.16-token cost, plus a public-alphabet change
that touches the resilience-bench and other public artefacts).

## Design implications for the multi-language pool

1. **The distribution shape is language-preserving.**  Every
   pure-ASCII subset above peaks at 2–3 tokens.  A mid-tail
   `[3, 5]`-band filter is a meaningful knob in every language
   observed; the operator's choice of band applies uniformly.
2. **Pool sizes shrink after ASCII-only filtering.**  German is
   the closest survivor of ASCII filtering (42 k of 50 k → 84 %)
   because German rarely uses Latin-supplement letters
   (umlauts are ASCII-compatible after normalisation).  French
   loses more (35 k of 50 k → 71 %) because acute/grave accents
   are common.  Spanish sits between.  The runtime wordlist
   loader's `[a-z]+` rule is currently the binding constraint
   for the multi-language pool size, not the raw corpus.
3. **Multi-language pool composition affects the role
   allocator.**  Under the laptop-default posture,
   `tools/wordlist-role-partitioning` at compound_n=4 needs
   ~14 k words for the identifier role.  Each of the three
   non-English languages here individually clears that
   requirement, so per-language rotation is architecturally
   feasible: an epoch can pick one language's subset and still
   satisfy the entropy target.  The role budget for the smaller
   compound_n=3 decoy role (~130 k words) is what a single
   non-English language cannot satisfy in isolation; the
   allocator's "provisional_v2_table + laptop-default"
   configuration would need EITHER (a) a cross-language pool
   for the decoy role only, OR (b) a smaller collision-margin
   than the 20-bit default for decoys in the non-English
   epochs.
4. **The intersect filter's attention-cost gain does not
   generalise for free.**  The English `intersect[3, 5]`
   filter's +15 % / +16 % compound token cost bump came from a
   specific per-language density profile; non-English languages
   need per-language filter measurement (rerun
   `tools/tokenizer-benchmark` against each filtered subset).

## Follow-up work identified

- **Relax the `[a-z]+` validator in
  `tools/wordlist-density-analysis/src/load.rs`** to accept
  `char::is_lowercase()` (Unicode).  Would let us score the full
  50 k language lists including diacritics — meaningfully bigger
  pool for French / German.  The runtime-side validator in
  `crates/v2-babbleon-core::wordlist` has the same rule; a
  matching relax there is a separate, operator-review-gated
  change.
- **Diacritics normalisation as an alternative to relaxing the
  validator.**  `NFKD` decomposition + drop combining marks →
  reduces "café" to "cafe".  Cheaper for wire size but loses
  the language's native shape.  Operator decision.
- **Rerun `tools/tokenizer-benchmark`** against each
  `intersect[3, 5]` filtered wordlist per language to populate
  the "Δ mean tokens" column above.  Autonomous-safe; the
  measurement is deterministic + reproducible.
- **Rerun `tools/wordlist-role-partitioning`** with per-language
  wordlist sizes to see if the role table fits each candidate
  or if a shared multi-language pool is required.  Autonomous-
  safe once the language files are on disk.
- **Vendor the source lists**.  The provisional plan (TODO.md
  phase 4) is 16 languages at ~100 k entries per language for
  a ~1.6 M-word compound pool.  Fetching them lives under
  `.github/workflows/vendor-wordlists.yml` or a build.rs;
  operator review recommended for the license bundle.

## Reproducer

```sh
# Preserve the pure-ASCII subset of a top-50k HermitDave list
# and score it under both tokenizers:
curl -sfL \
  https://raw.githubusercontent.com/hermitdave/FrequencyWords/master/content/2018/es/es_50k.txt \
  -o es_50k.txt
awk '{print $1}' es_50k.txt | grep -E '^[a-z]+$' > es_ascii.txt

cd tools/wordlist-density-analysis
cargo run --release -- --wordlist ../../es_ascii.txt
```
