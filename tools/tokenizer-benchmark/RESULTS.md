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

**Implications:**

1. The token-cost lever is **not load-bearing** for the threat model.
   Babbleon's defense rests on namespace rename + tier boundary +
   tripwires.  Tokenization friction is, at most, a marginal cost
   multiplier on the attacker's recon step.
2. No PLAN-level or README-level claim about token-cost should be
   restored without re-running this benchmark with the exact wordlist,
   seed, and tokenizer versions the claim cites.
3. The 7 % delta is real and consistent across N=3,4,5 and across both
   tokenizers, but it is too small to advertise as a defense.

## Future work

- Re-measure after the wordlist gets the RESEARCH T6 v2 post-filter
  (tokenization-density bias toward mid-tail tokens).  That is the only
  configuration that could move the ratio meaningfully.
- Try Claude's tokenizer via the count-tokens API; tiktoken is
  OpenAI-specific.
- Try SentencePiece (Llama 3) — different algorithm, possibly
  different result.
