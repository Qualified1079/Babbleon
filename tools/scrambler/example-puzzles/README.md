# Scrambler example puzzles

Five Python puzzles of increasing difficulty.  Each file has a single
`# {{INSERT}}` marker showing where exactly one missing line lives.
The harness (`../index.html`) scrambles identifiers and string
contents; the LLM under test sees the scrambled source plus the
hint comment at the top, and must emit a one-line completion.

Difficulty marked in the file header (1–5):

| File | Topic | Difficulty |
|---|---|---|
| `01-fizzbuzz.py` | classic FizzBuzz | 1 |
| `02-running-max.py` | running maximum over a list | 2 |
| `03-anagram-groups.py` | bucket words by sorted-letter signature | 3 |
| `04-balanced-parens.py` | stack-based bracket validator | 3 |
| `05-merge-intervals.py` | merge overlapping intervals | 4 |

## How to run an experiment

1. Open `../index.html` in a browser.
2. Pick a seed (anything — keep a note of it; the same seed gives
   the same scramble).
3. Paste one of the puzzle files into the left panel; click "scramble".
4. Send the scrambled source to your LLM along with the hint comment
   from the top of the file.  Do NOT send the original — that defeats
   the experiment.
5. Paste the LLM's one-line response into the right panel; click
   "unscramble".
6. Paste the unscrambled line at the `{{INSERT}}` marker in the
   original file and run it.  `print("ok")` means the test passed.

## What the puzzles isolate

These deliberately test ONLY the naming-obfuscation layer.  Python
keywords, operators, and overall control flow are visible.  This
is the **weakest** form of the full Babbleon defense: a real attacker
against the production stack sees stripped binaries with mangled
`--help`, no source, no syntax.

If a frontier LLM fails these puzzles consistently, the full defense
is decisively stronger.  If a frontier LLM succeeds, that measures
the naming layer's individual contribution — not the full system.

## Filed follow-ups

- More puzzles: type-juggling, async, exceptions, dict-comprehension
  rewriting.
- A separate set in C and Rust — both are common attacker-toolchain
  languages and have different identifier-density profiles.
- A scoring harness that automates the "paste-to-LLM, paste-back,
  run-tests" loop against an API endpoint.
