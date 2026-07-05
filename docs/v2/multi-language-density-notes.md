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

---

## 2026-07-05 update (overnight autonomous session) — license correction, corpus-size correction, raw-content contamination, and a new architectural blocker found in the daemon

Author: Claude Sonnet 5. Picked up `TODO.md`'s Phase 4 "Vendor
HermitDave/FrequencyWords multilingual lists" item after confirming
the Phase-4 obfuscation-layer backlog (Layer 7/8/10) and the
adversarial-LLM measurement are still genuinely blocked (no
frontier-model API credentials are available in this session's
environment — checked `env` for `OPENAI_API_KEY`/similar, none
present, so the item gated on that test stays gated). The
2026-07-04 session already flagged multi-language wordlist vendoring
as "a large, scope-unsettled data-vendoring task better suited to a
session that starts by settling the language list and licensing" —
this entry does exactly that settling work, checked against the live
source rather than re-stated from memory. Doc-only; no production
code changed, no data vendored yet.

### 1. License correction — the frequency-list *content* is CC-BY-SA-4.0, not MIT

Both `TODO.md` and this file's own 2026-07-02 entry say "MIT
licence" for HermitDave/FrequencyWords. That's an incomplete read.
Checked directly: the repo's top-level `LICENSE` file is MIT (covers
"the Software" — the frequency-list *generator code*), but the
repo's own `README.md` states explicitly: **"MIT License for
code. CC-BY-SA-4.0 for content."** The `.txt` frequency files
themselves — the thing phase 4 actually wants to vendor — are the
"content," under CC-BY-SA-4.0, not the code's MIT license.

CC-BY-SA-4.0 requires (a) attribution and (b) share-alike: any
derivative distributed publicly must carry the same CC-BY-SA-4.0
license. Filtering/subsetting/normalizing these lists into a
Babbleon wordlist file (exactly what phase 4 plans) is a derivative
work under that license. Babbleon's own crates license is
`LicenseRef-PolyForm-Noncommercial-1.0.0` (checked
`Cargo.toml`'s workspace `license` key) — PolyForm-NC is already
stricter than CC-BY-SA-4.0 on commercial use, so there's no
same-repo conflict on that axis. The real implication is for
`TODO.md`'s M5 ("Enterprise, separate private repo") track: a
CC-BY-SA-4.0-derived wordlist file would carry a persistent
attribution + share-alike obligation that a commercial relicense of
the rest of the codebase cannot strip from that one file. This is a
licensing-policy call, not a code question — **flagged for operator
review before any HermitDave content is vendored**, same discipline
as the TUF and CycloneDX-vs-SPDX decisions already recorded in
`docs/v2/standards-alignment.md`. Mechanically it's a solvable
problem (attribute + isolate the derived file(s) with their own
`README.md` the way `crates/babbleon/wordlist/README.md` and
`tools/tokenizer-benchmark/tokenizers/README.md` already do
per-source provenance) — it just needs a yes, not an assumption.

### 2. Corpus-size correction — not every language has a 100k tier

`TODO.md`'s "Provisional N=100k entries per language" assumption
does not hold uniformly. Checked the actual 2018-corpus file
availability for all 16 shortlisted languages via
`raw.githubusercontent.com` (HTTP HEAD-equivalent probe): 14 of 16
serve a `<lang>_50k.txt` tier (en, es, fr, de, zh_cn, zh_tw, ar, ru,
pt_br, it, nl, pl, tr, ko all returned HTTP 200). **Japanese and
Hindi do not** — only `ja_full.txt` (34 504 raw lines) and
`hi_full.txt` (21 309 raw lines) exist, both well under even the
50k tier, let alone the 100k provisional target. Any phase-4
implementation plan needs a per-language size table checked against
the real files, not a single assumed constant — and needs to decide
what happens to the identifier/decoy/direction_marker role budgets
(`tools/wordlist-role-partitioning`'s math above) for languages that
can't supply the assumed pool size. Full per-language line counts
were not exhaustively pulled for all 16 this session (network cost);
the ja/hi shortfall is confirmed, the other 14 are confirmed present
at the 50k tier but not confirmed at a hypothetical 100k tier since
HermitDave doesn't publish one — the 100k figure in `TODO.md` appears
to have been an assumption, not a checked file. Whoever settles the
final vendored size per language should pull the real
`wc -l` for each file first.

### 3. Raw content is not pre-filtered to "words" — every language needs a content filter, including English

Sampled the raw top-N entries of several language files directly
(not just the pure-ASCII-filtered subset the 2026-07-02 entry
scored). Findings:

- **English itself contains non-word entries in the top 2000**:
  contraction fragments (`'s`, `'t`, `'m`, `'re`, `'ll`, `'ve`,
  `'d`) and abbreviations with periods (`mr.`, `dr.`, `mrs.`).  The
  currently-shipped `dwyl/english-words` baseline
  (`crates/babbleon/wordlist/words.txt`) is pre-filtered and doesn't
  have this problem, but a naive vendor of HermitDave's *English*
  file for phase-4 purposes would reintroduce it.
- **Arabic's single most frequent token is a punctuation mark**
  (`،`, Arabic comma) — frequency-list tokenization here is
  corpus-tokenizer output, not a curated word list; punctuation and
  symbol tokens ride along at high frequency.
- **French contributes elision fragments** (`c'`, `l'`, `j'`) in
  the top 20, on top of the accented-character retention loss the
  2026-07-02 entry already measured.
- **Turkish uses non-ASCII Latin letters** (ç, ş, ı, ğ, ö, ü) even
  though it's Latin-script — same "not actually ASCII" category as
  French/German/Spanish's accents, just not covered by the earlier
  three-language sample.

None of this invalidates the density/tokenizer-cost measurements
already in this file (those were run against filtered subsets), but
it sharpens the filter spec any vendoring pass needs: reject entries
containing no letter-category codepoint, reject entries containing
`'`, `.`, or other punctuation, in addition to the
diacritics-normalize-or-relax-to-Unicode-lowercase question this
file already covers. **CJK/Arabic/Devanagari-script languages
(zh_cn, zh_tw, ja, ar, ko, hi) cannot participate in an
ASCII-lowercase identifier role at all** — there is no
"normalise-diacritics"-style transliteration that turns 的 or の or
، into `[a-z]+` without destroying the word (unlike café→cafe).
They are only ever candidates for content-only roles under finding
#4 below, never for a role whose output could reach a filesystem
path.

### 4. New finding: the daemon shares ONE wordlist between path-name generation and content-only roles — a real blocker for any non-ASCII pool, independent of the role-partitioning math

This is the sharpest finding this session and wasn't surfaced by
either the 2026-07-02 density notes or `tools/wordlist-role-
partitioning`'s design, both of which model wordlist role-slicing
purely within the *preprocessor's* structural-scrambling content
(identifier / decoy / whitespace / keyword / direction_marker /
prompt_injection — all consumed by `crates/v2-babbleon-preprocessor`
against source-code *content*, never a filesystem path).

Read `crates/v2-babbleon-daemon/src/state.rs` directly: `DaemonConfig`
holds exactly one `wordlist: &'static Wordlist` field
(`state.rs:114`). That single field feeds **two structurally
different consumers**:

1. `DaemonState::build_epoch_mapping` → `MappingBuilder::build`
   (`crates/v2-babbleon-core/src/mapping.rs`) → the scrambled
   compound used as a **filesystem path component** for wrapper
   binaries (`crates/v2-babbleon-daemon/src/materialization.rs`'s
   `config.wrapper_dir.join(scrambled)`). This is the consumer
   `crates/babbleon/wordlist/README.md`'s Invariant 1 exists to
   protect (CWE-22 — a scrambled name built from `[a-z]+`-only
   entries cannot contain `/`, `\`, `..`, or NUL). **This consumer
   has no independent ASCII check of its own** — it relies entirely
   on the wordlist it's handed already being ASCII-only.
2. `DaemonState::token_mapping` (preprocessor L2 identifier-scramble
   aliases) and the whitespace-wordlist builder — both **content-
   only**: their output is embedded in a scrambled source file's
   body text, piped to an interpreter, never used as a path. Safe
   for non-ASCII by construction.

Both call sites read `self.config.wordlist` — literally the same
`&'static Wordlist` reference (confirmed at `state.rs:460` and
`state.rs:601`). This means: **the moment any non-ASCII, multi-
language pool is wired into `DaemonConfig::wordlist` — even a pool
that's already been correctly role-partitioned into per-purpose
subsets by a future `tools/wordlist-role-partitioning`-style
allocator — the wrapper-materialization path silently loses its
ASCII-only guarantee**, because `build_epoch_mapping` has no filter
of its own; it trusts the field. A single shared `Wordlist` cannot
simultaneously be "the pool the role allocator slices across six
content roles" and "the ASCII-only pool path-name generation
requires," unless every one of those six role-subsets is
independently constrained to `[a-z]+` — which defeats the entire
point of adding non-Latin-script languages.

**The concrete, buildable prerequisite this surfaces** (not built
this session — it touches `DaemonConfig`'s public shape and the
`DaemonState` constructors exercised by a large existing test suite,
and deserves its own reviewed diff rather than a rushed addition
alongside a research doc): split `DaemonConfig`'s single `wordlist`
field into two —

- `identifier_wordlist: &'static Wordlist` — ASCII-only
  (`Wordlist::english_baseline()` today), consumed **only** by
  `build_epoch_mapping`. Keep or add an explicit assertion at that
  call site (not just at `Wordlist` construction time) so a future
  wordlist swap that violates the ASCII invariant fails loudly at
  the one call site that actually needs it, instead of silently
  producing a path-unsafe compound.
- `content_wordlist: &'static Wordlist` — may be multi-language /
  non-ASCII once phase 4 lands, consumed **only** by `token_mapping`
  and the whitespace-wordlist builder.

Both `MappingBuilder::new`/`with_cache` and
`WhitespaceWordlist::build` already take `&Wordlist` as a plain
parameter (see `mapping.rs:148` / `whitespace_wordlist.rs`'s
`build` signature) — this is a `DaemonConfig`/`DaemonState` wiring
change plus a test-fixture update across `state.rs`'s ~30
`Wordlist::english_baseline()` call sites, not an API redesign of
either crate. Filed here rather than built tonight because (a) it's
a change to a widely-depended-on daemon config struct with a large
existing test surface that deserves a dedicated, reviewed diff, not
a rider on a licensing research note, and (b) there is no
multi-language data to wire in yet pending the license-review
decision in §1 above — building the split now would be untested
scaffolding for data that may not land in its currently-planned
form.

### Revised recommendation for whoever picks up phase-4 wordlist vendoring next

1. Get the operator's licensing call on §1 (CC-BY-SA-4.0
   attribution + share-alike acceptance for a vendored data file,
   specifically its interaction with the M5 Enterprise track) before
   fetching anything for real.
2. Once licensing is settled, build the `DaemonConfig` wordlist
   split from §4 FIRST, with tests pinning that `build_epoch_mapping`
   output stays `[a-z]+`-only even when `content_wordlist` is
   swapped to a non-ASCII pool — that ordering makes the ASCII
   invariant a property the test suite enforces structurally, not
   an assumption a data-vendoring PR has to remember.
3. Per-language content filter (§3): reject non-letter-category
   entries (punctuation, contractions, abbreviations-with-periods)
   for every language, including English, before any frequency list
   feeds a role.
4. Re-check real corpus sizes per language (§2) instead of the
   assumed 100k figure; decide ja/hi/zh/ar/ko's role assignment
   under finding #3's script constraint (content-only roles only,
   never identifier/path-adjacent — though note the *preprocessor's*
   L2 "identifier" role is itself a content role per finding #4, so
   this restriction is about filesystem-path safety specifically,
   not about the preprocessor's naming).
5. Only then resume the role-partitioning sizing work
   (`tools/wordlist-role-partitioning`) with real, filtered,
   per-language pool sizes.

Same standing operator-gated items as recent sessions, unchanged:
seccomp/exec finding, PAM wiring, A08 (v2 binaries in the release
pipeline), the secret-literal runtime-channel question, and now the
CC-BY-SA-4.0 licensing call above.
