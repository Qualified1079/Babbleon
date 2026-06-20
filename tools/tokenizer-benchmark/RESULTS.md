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
