# preprocessor-benchmark

Per-file latency microbenchmark for the v2 layer-3 preprocessor
(tokenize + scramble + unscramble pipeline).

## What it answers

`docs/v2/structure-scrambling.md` §"Recommended phase-3 prototype"
step 5: confirm that the preprocessor is well under 50 ms per file
on the same hardware tier as the existing `tools/rotation-benchmark/`
runs, before the phase-3 MVP escalates to the operator's
adversarial-LLM test.

## Run it

```
cd tools/preprocessor-benchmark
cargo build --release
./target/release/preprocessor-benchmark
```

By default it runs 1000 timed iterations (plus 100 warmup) per
puzzle in `tools/scrambler/example-puzzles/`.  Flags:

| Flag | Default | Meaning |
|------|---------|---------|
| `--puzzles-dir PATH` | `../scrambler/example-puzzles` | Where the .py corpus lives. |
| `--iterations N` | 1000 | Timed iterations per puzzle. |
| `--warmup N` | 100 | Warmup iterations (excluded from stats). |
| `--target-micros N` | 50000 | Phase-3 median target.  Exit code 1 if any puzzle's median exceeds it. |
| `--epoch N` | 0 | Epoch for the whitespace-wordlist derivation.  Bumping it tests epoch-independence of the timing. |

## What it measures

For each puzzle, end-to-end:

1. `tokenize(source) -> Vec<Token>` (Python tokenizer pass)
2. `scramble(&tokens, &wl) -> String` (per-epoch compound substitution)
3. `unscramble(&scrambled, &wl) -> String` (greedy prefix match + canonical re-emission)

The `WhitespaceWordlist` is derived once, before the timing loop —
the daemon caches the same mapping across requests in production
(`v2-babbleon-daemon::state::DaemonState::cached_mapping`), so the
benchmark matches the steady-state cost the operator sees.

## What it does NOT measure

- Daemon socket round-trip to fetch compounds (one-shot per CLI
  session, ~4 KiB JSONL, amortises to zero).
- File I/O for the puzzle source (read once before the loop).
- Argon2id at-rest vault unseal (cold path, not the per-file cost).

The phase-3 spec's 50 ms target is the **local compute path** — what
this binary measures end-to-end.
