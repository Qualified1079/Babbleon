# Wordlist invariants

`words.txt` is the source of every scrambled name Babbleon produces.
Several of the security claims in `docs/cwe-top25-audit.md` and
`docs/threat-model-stride.md` depend on properties of this file.
Bumping or replacing the wordlist demands re-checking all of them.

## Invariant 1 — Every line matches `^[a-z]+$`

Closes **CWE-22 (path traversal)** for every scrambled wrapper name.
A scrambled name is the concatenation of N wordlist entries; if every
entry is lowercase-alpha only, the concatenation cannot contain `/`,
`\\`, `..`, or NUL.  The wrapper writer doesn't have to sanitize.

Regression test: `tests::wordlist_is_lowercase_alpha_only` in
`mapping/mapper.rs`.

## Invariant 2 — At least ~370k distinct entries

Defends the per-host adaptation gap in **STRIDE I1 / E4-shaped
threats** (per-host random mapping must not collide trivially).
A 4-word compound from a 370k-entry list draws from `370k^4 ≈ 1.9e22`
possibilities — comfortably above the collision floor at any
realistic host count.

Regression test: a `const_assert!` on `WORDLIST_RAW.lines().count()`
in `mapping/mapper.rs` would be ideal once that's not slow at
compile time; for now the test verifies a lower bound at runtime.

## Invariant 3 — Tokenization cost is roughly uniform

The tokenizer benchmark (`tools/tokenizer-benchmark/`) measured the
BPE token cost of compound names at ~1.07× the spaced-English
baseline on cl100k_base / o200k_base.  This number is reported in
`PLAN.md` §5 and depends on the wordlist's distribution looking like
"natural English words a tokenizer was trained on".  Replacing the
wordlist with, e.g., pinyin or a domain-specific glossary changes
this number — re-run the benchmark and update the figure.

## Source

`dwyl/english-words` (https://github.com/dwyl/english-words),
Unlicense.  Filtered to lowercase ASCII a-z entries only.  Original
file is ~466k entries; after filtering ~370k remain.

## Replacing the wordlist

1. Run the filter:
   `grep -E '^[a-z]+$' < source.txt > words.txt`
2. Confirm Invariant 1 still holds:
   `! grep -v '^[a-z]\\+$' words.txt`
3. Confirm Invariant 2 still holds:
   `wc -l words.txt`  (need ≥ 200k for safety margin)
4. Re-run the tokenizer benchmark to refresh Invariant 3:
   `cargo run -p tokenizer-benchmark --release`
5. Rebuild + retest the workspace.
6. Bump `BUNDLE_SCHEMA` only if removed entries break old backups
   (they do — `backup.rs` checks `wordlist_sha256`).
