# Tokenizer benchmark — results

First-pass measurement of token-count inflation for Babbleon scrambled
compounds vs a matched spaced-English baseline.

## Run conditions

- Wordlist: `crates/babbleon/wordlist/words.txt` (369 652 usable
  lowercase ASCII words after filtering).
- Tokenizers: `tiktoken-rs` 0.5.9, `cl100k_base` and `o200k_base` cached
  BPE tables.
- Seed: `0xbabb1e0011223344`.
- Sampling: words drawn independently per sample, same draw used for
  both conditions to isolate the no-whitespace effect from word
  frequency.

| N (words / compound) | Samples | Tokenizer    | mean ratio (compound / spaced) | median ratio |
|----------------------|---------|--------------|--------------------------------|--------------|
| 3                    | 5 000   | cl100k_base  | 1.060×                         | 1.000×       |
| 3                    | 5 000   | o200k_base   | 1.068×                         | 1.000×       |
| 4                    | 1 000   | cl100k_base  | 1.068×                         | 1.071×       |
| 4                    | 1 000   | o200k_base   | 1.073×                         | 1.077×       |
| 5                    | 5 000   | cl100k_base  | 1.070×                         | 1.067×       |
| 5                    | 5 000   | o200k_base   | 1.079×                         | 1.071×       |

## Honest interpretation

The token-cost inflation we measured is **~7 %**, not the 2–3× that
RESEARCH.md T6 hypothesized.  The hypothesis was extrapolated from
prior literature on adversarial / randomized strings; English-word
compounds drawn from a 370k-word list are recognizable enough to the
BPE tokenizers that the no-separator penalty is small.

Two important caveats on what this number even *means*:

1. **Recon token cost ≠ exploit-execution capability.** The tokenizer
   penalty taxes the attacker's input-encoding step; it does not
   change whether the attacker can compile a working payload once it
   has the names.  Quoting a "Babbleon makes attacks 7 % more
   expensive" line would conflate input-encoding cost with end-to-end
   attack cost, which it is not.  No such line should appear in
   user-facing copy.
2. **Tokenizer behavior is measured on `cl100k_base` / `o200k_base`
   (OpenAI families).**  These are near-frontier tokenizers.  Smaller
   open-weights models often use smaller, less-saturated tokenizers
   (Llama-3 SentencePiece, Mistral, Phi) where the no-whitespace
   penalty is plausibly larger; the inflation may scale superlinearly
   as model size shrinks.  This is a *hypothesis*, not a measurement;
   see the SentencePiece follow-up below.

## Implications for the design

The token-cost lever is **not load-bearing** for the threat model.
Babbleon's defense rests on namespace rename + tier boundary +
tripwires.  Tokenization friction is, at most, a marginal cost
multiplier on the attacker's recon step — keep around as data, do not
advertise.

No PLAN-level or README-level claim about token-cost should be
restored without re-running this benchmark with the exact wordlist,
seed, tokenizer, and model-family the claim cites.

## Future work

- ~~Try SentencePiece (Llama 3, Mistral) and the smaller open-weights
  tokenizers~~ — **done 2026-07-04**, see "SentencePiece open-weights
  tokenizer comparison" below: null result, hypothesis does not hold.
  (Llama-3's own tokenizer specifically was not tried — its
  `tokenizer.json` is gated behind a license click-through on
  HuggingFace; Mistral-7B-v0.1 and Phi-2 are both open and were used
  instead as representative smaller/open-weights vocabularies.)
- Try Claude's tokenizer via the count-tokens API; tiktoken is
  OpenAI-specific.
- Re-measure after the wordlist gets the RESEARCH T6 v2 post-filter
  (tokenization-density bias toward mid-tail tokens).  That is the
  only wordlist-side configuration that could move the ratio
  meaningfully on cl100k/o200k.
  **Update 2026-07-02:** the mid-tail filter analysis landed in
  `tools/wordlist-density-analysis/`.  Re-measuring compound cost
  against each candidate filter's output confirmed that the
  compound-to-spaced *ratio* does **not** move meaningfully
  (~1.07× across every filter) — the filter changes the absolute
  compound cost (+8.8 % to +16.1 % vs baseline, depending on
  tokenizer × band), not the no-whitespace penalty.  These are
  independent signals.  See
  `tools/wordlist-density-analysis/RESULTS.md` for the full matrix
  including the intersection filter, which achieved +15.4 % /
  +16.1 % compound-cost inflation on cl100k / o200k for 223 009
  kept entries.

## Smaller-model tokenizer comparison (2026-07-02 session 2)

TODO.md phase 4 supporting research asked: "Do smaller-vocab
tokenizers (GPT-3-era) cost MORE per Babbleon compound than
GPT-4-era ones?"  The bench grew a `--include-smaller` flag that
adds `r50k_base` (GPT-3, 50 k vocab) and `p50k_base` (Codex,
50 k vocab).  One representative run:

- English baseline wordlist, 2 000 samples, seed=1, `--compound-n 4`.

| Tokenizer     | Vocab  | Compound mean | Spaced mean | Ratio (compound / spaced) |
|---------------|-------:|--------------:|------------:|--------------------------:|
| `o200k_base`  | 200 k  |         11.54 |       10.85 |                    1.070× |
| `cl100k_base` | 100 k  |         11.97 |       11.33 |                    1.062× |
| `p50k_base`   |  50 k  |         12.35 |       11.67 |                    1.066× |
| `r50k_base`   |  50 k  |         12.35 |       11.67 |                    1.066× |

**Findings.**

1. **Smaller-vocab tokenizers cost more in absolute tokens.**
   Compound mean drops from 12.35 (r50k/p50k) → 11.97 (cl100k) →
   11.54 (o200k) — an ~7 % absolute reduction as vocab quadruples.
2. **The compound-to-spaced ratio is tokenizer-invariant** (1.062–
   1.070×).  The hypothesis that smaller tokenizers show a
   *superlinear* compound tax does NOT hold in this run —
   spaced-baseline cost scales at the same rate, so the ratio
   stays flat.
3. **`p50k_base` == `r50k_base`** on this input.  Expected: p50k
   is a strict superset of r50k for the "text" register, and the
   words in the Babbleon wordlist land in that subset.
4. **Design implication.**  Deploying against LLMs that use
   r50k/p50k-shaped tokenizers gives ~3 % *more* absolute attention
   cost per compound than the current cl100k baseline.  So a
   Babbleon build tuned for GPT-3-era targets does NOT need a
   different filter strategy from a GPT-4-era build — the ratio
   is what matters for the obfuscation gain, and it is invariant.

## SentencePiece open-weights tokenizer comparison (2026-07-04)

Closes the "Tokenizer benchmark — smaller-model tokenizers" item and
the "smaller open-weights tokenizer pays a superlinear compound tax"
hypothesis that the tiktoken-only measurements above (§"Honest
interpretation" caveat 2) could not test, because `tiktoken-rs` only
covers OpenAI's own BPE families. The bench grew an
`--include-sentencepiece` flag using the `tokenizers` crate (pure
Rust, HuggingFace) loading two vendored, openly-licensed
`tokenizer.json` files under `tools/tokenizer-benchmark/tokenizers/`
— see that directory's `README.md` for exact source URL, license, and
sha256:

- **`mistral-7b-v0.1`** — Mistral AI's SentencePiece BPE tokenizer
  (32 000 vocab), Apache-2.0.
- **`phi-2`** — Microsoft's tokenizer (50 295 vocab, GPT-NeoX-style
  BPE — not Unigram SentencePiece specifically, but the smaller,
  non-frontier open-weights vocabulary the hypothesis is actually
  about), MIT.

Two independent runs, same wordlist, `--compound-n 4`, 2 000 samples
each, different seeds — checking the result isn't a seed artifact
before citing it:

| Tokenizer            | Vocab   | Seed         | Compound mean | Spaced mean | Ratio (compound / spaced) |
|-----------------------|--------:|--------------|---------------:|------------:|--------------------------:|
| `mistral-7b-v0.1`     |  32 000 | `0xbabb1e0011223344` |          12.97 |       12.52 |                    1.041× |
| `mistral-7b-v0.1`     |  32 000 | `0xdeadbeef`         |          12.85 |       12.38 |                    1.044× |
| `phi-2`               |  50 295 | `0xbabb1e0011223344` |          12.41 |       11.66 |                    1.072× |
| `phi-2`               |  50 295 | `0xdeadbeef`         |          12.28 |       11.54 |                    1.072× |
| `cl100k_base` (same run, for reference) | 100 000 | `0xbabb1e0011223344` | 12.01 | 11.31 | 1.069× |
| `o200k_base` (same run, for reference)  | 200 000 | `0xbabb1e0011223344` | 11.61 | 10.87 | 1.076× |

**Findings.**

1. **The superlinear-scaling hypothesis does NOT hold, across two
   different open-weights vocabularies.** Mistral's 32k-vocab
   tokenizer actually shows a slightly *lower* compound/spaced ratio
   (~1.04×) than any OpenAI tiktoken family measured so far — the
   opposite direction from "smaller vocab pays more." Phi-2's
   ratio (~1.072×) lands right in the middle of the tiktoken cluster
   (1.062×-1.083× across all prior runs in this file), not above it.
2. **Consistent with the r50k/p50k finding above.** Combined with the
   2026-07-02 result (smaller OpenAI-family vocabularies also show a
   flat, not superlinear, ratio), this is now two independent lines
   of evidence — one within the OpenAI tiktoken family, one across
   entirely different tokenizer training pipelines (SentencePiece,
   GPT-NeoX-style) — against the hypothesis. `RESEARCH.md`'s
   "smaller-model superlinear" open question (also tracked in
   `TODO.md`) should be treated as answered (null result), not still
   open, absent a specific reason to doubt these two runs.
3. **Absolute compound cost still varies by vocab size** (Mistral
   12.9-13.0 tokens vs Phi-2 12.3-12.4 vs cl100k 12.0 vs o200k 11.6),
   same pattern as the r50k/p50k comparison — smaller vocabularies
   cost more tokens in absolute terms, but the *ratio* (the actual
   obfuscation-relevant number) stays in the same ~1.04×-1.08× band
   regardless of tokenizer family or vocab size.
4. **Design implication — unchanged from the r50k/p50k finding**,
   now on firmer footing: Babbleon's wordlist-compound design does
   not need a different strategy for open-weights-model-shaped
   attackers than for OpenAI-shaped ones. The token-cost lever
   remains not load-bearing for the threat model (per "Implications
   for the design" above) regardless of which tokenizer family the
   attacker's LLM uses.

Still open (not this item): the Claude tokenizer via the count-tokens
API — a different measurement path (network API call, not a vendored
local table) that this session did not attempt; see `TODO.md`.
