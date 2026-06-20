# tokenizer-benchmark

Empirical measurement of BPE token-count cost for Babbleon scrambled
compound names vs a matched spaced-English baseline.  Pure data; no
production effect, no design coupling.

## Why this exists

RESEARCH.md T6 hypothesized that lowercase-concatenated 4-word
compounds (`riverstoneanvilfreckle`) impose a 2–3× token-cost tax on a
BPE tokenizer compared to spaced English of the same word content.
That number was extrapolated from prior literature on randomized /
adversarial strings.  This binary measures it directly on the
production wordlist.

The actual measured ratio is ~1.07×.  See `RESULTS.md`.

## Build and run

This crate is **standalone** — it has its own `[workspace]` table so
it is not part of the main Babbleon workspace, keeping `tiktoken-rs`
out of the default `cargo build --workspace` path.

    cd tools/tokenizer-benchmark
    cargo run --release -- --samples 1000

Options:

    --samples N        samples per condition (default 1000)
    -n, --compound-n   words per compound (default 4)
    --wordlist PATH    wordlist file (default ../../crates/babbleon/wordlist/words.txt)
    --seed S           ChaCha20 seed for word picks (default fixed; runs reproducibly)
    --out PATH         optional per-sample CSV output

## What it measures

For each sample, draws N words from the wordlist.  Concatenates them
(compound condition) and joins them with single spaces (control
condition).  Tokenizes both with `cl100k_base` and `o200k_base`.
Reports distributions of token counts and the per-sample ratio.

Same word draw is used for both conditions, so the only difference
between conditions is the whitespace.  Word frequency, length, and
choice are controlled for.

## Reporting policy

The benchmark prints a final reminder: any quantitative claim about
token-cost in PLAN.md or README must cite the wordlist, seed, and
sample size that produced it.  Do not generalize from one run to "what
Babbleon does to tokenizers" without re-running.
