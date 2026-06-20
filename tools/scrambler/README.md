# Babbleon Scrambler — adversarial test harness

A single-file HTML page that demonstrates Babbleon's naming layer against
an LLM solver, with you as the man-in-the-middle.

Open `index.html` in a browser. No server, no dependencies.

## Workflow

1. **Pick a seed** — type anything in the seed box, or click "random". The
   same seed always produces the same scrambling, so both sides of the
   round trip work.
2. **Paste a puzzle** — left panel. A small Python program with the line
   `# {{INSERT}}` marking where a single line of code is missing.
   Example puzzles ship in `tools/scrambler/example-puzzles/` (TBD).
3. **Scramble** — left panel button. Identifiers and string contents get
   replaced with 4-word lowercase compounds drawn from a 2048-word list.
   Python keywords (`def`, `for`, `return`, ...) and operators stay intact
   so the puzzle remains parseable.
4. **Send the scrambled output to an LLM** — include the hint about what
   to insert at the `{{INSERT}}` marker. The LLM responds with one or more
   lines using whatever names it sees in the scrambled source.
5. **Paste the LLM's response** — right panel. Click "unscramble". You get
   the LLM's insertion translated back to the original identifiers.
6. **Substitute and run** — paste the unscrambled line at the `{{INSERT}}`
   marker in your original program, run it, check the output.

## What's being tested

The naming-obfuscation layer of Babbleon, in isolation. This is the
*weakest* form of the full defense — a scrambled-source puzzle still leaks
Python syntax (`for`, `if`, `def`), control flow, literal values, and
overall structure. A real attacker against full Babbleon sees stripped
binaries with mangled `--help`, no comments, no syntax — much less.

If an LLM solver fails this puzzle, the full defense is decisively
stronger. If it succeeds, you've measured the strength of the naming layer
only, not the full system.

## Implementation notes

- Wordlist is embedded; ~20 KB inline. Same algorithm shape as the Rust
  Mapper but with a non-cryptographic FNV-1a hash chain (we don't need
  CSPRNG-grade pseudorandomness here — only deterministic invertibility).
- Tokenizer is heuristic: handles single-quoted and double-quoted single-line
  strings, line comments, and standard identifiers. Triple-quoted strings,
  f-strings, and multiline strings are NOT handled cleanly yet — keep puzzles
  to simple Python.
- Mapping cache lives in JS memory only. The reverse-unscramble in panel 2
  requires that you scramble first in panel 1 (so the inverse table is
  available). Reload = lose the mapping (a fresh scramble of the same source
  with the same seed reproduces it).
