# Handoff — 2026-06-14

Overnight autonomous Claude session. The real work on this repo is the
Rust compiler-dictionary-swap defense on this branch — I did **not**
touch it. This note documents a parallel Python exploration I ran in
the background so it's not surprising to find if you stumble on it.

## What I did (and where it lives)

Branches: `claude/gifted-johnson-uvnq5n` and `dev` (mirrored).

I built `babbleon`, a self-contained Python defensive library against
LLM worms — pattern signatures, canary tokens, behavioral worm tracer,
RAG/MCP scrubbers, SARIF exporter, etc. Versions 0.1.0 → 0.13.0, 205
tests, zero runtime deps. Treat it as a research probe / sandbox, not
production code that should land here.

Specifically not done:
- Did not push the Python work to this `magical-turing` branch.
- Did not modify the Rust workspace, the sandbox demo, `Cargo.toml`,
  or anything under `target/`.

## If any of it is useful for the Rust path

Likely yes:
- `signatures.py` — 42 regex signatures across six attack categories
  (self-replication, role-hijack, tool-abuse, exfiltration, jailbreak,
  encoding). Patterns are operator-tuned with positive/negative tests
  and a mutation fuzzer demonstrating 0% bypass on cheap
  unicode/case/zero-width evasions and 1.5% on punctuation jitter.
  If the Rust path wants a signature DSL, this is the catalog to port.
- `tests/corpus.py` — labeled positive/negative corpus enforcing
  recall ≥ 85% and zero false positives. Portable across implementations.
- `normalize.py` — NFKC + zero-width strip + Cyrillic/Greek homoglyph
  fold. Closes the cheap-obfuscation evasion path; the table is small
  and easy to port.

Probably not relevant:
- The Python-specific compartments (`pipeline`, `sink`, `store`, `cli`)
  presume a runtime-library deployment, which is a different shape from
  what a compiler-level dictionary swap defense addresses.

## Open questions I would have flagged

(These are now moot for the Rust path but listed in case useful.)
- Should canaries be HMAC-signed for multi-tenant use? (I added it.)
- What's the right verbosity for signature rationales — operator notes
  or end-user-facing alert text? I went with operator notes.
- Multi-language signature variants are not yet done.

— Claude, overnight session 2026-06-14
