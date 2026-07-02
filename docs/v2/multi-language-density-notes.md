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

| Language  | Input  | Kept (intersect[3,5]) | Kept % | Δ mean tokens |
|-----------|-------:|----------------------:|-------:|--------------:|
| English   | 369 652 |             223 009  | 60.3 % |    +15.4 % / +16.1 % (cl100k / o200k) |
| German    |  42 179 |              …       | tbd    | tbd           |
| Spanish   |  40 236 |              15 485  | 38.5 % | tbd (need bench) |
| French    |  35 433 |              …       | tbd    | tbd           |

Spanish's `intersect[3, 5]` retention (38.5 %) is much lower than
English's (60.3 %) because the pure-ASCII Spanish top-50k is
biased toward short common words (43 % score 2 tokens under
cl100k, vs English's ~30 %).  The mid-tail (3–5 tokens) covers a
smaller fraction of the distribution.  The other language rows
are unpopulated because the compound-cost benchmark
(`tools/tokenizer-benchmark`) needs to be rerun against each
filtered wordlist; that is a small follow-up cost, not a design
question.

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
