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

- Try SentencePiece (Llama 3, Mistral) and the smaller open-weights
  tokenizers — the smaller-model superlinear-scaling hypothesis can
  only be checked there.  Different algorithm (Unigram LM), possibly
  meaningfully different result.
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
