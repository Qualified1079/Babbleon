# Dynamic keyword extraction — v2 design

Layer 2 of v2's structural scrambling (operator scramble) needs
to know which tokens in a source file are reserved keywords that
must be routed to the operator wordlist pool rather than the
identifier pool.  This document describes how v2 extracts and
manages those keyword sets.

## The problem

A naive approach hard-codes per-language keyword lists:

```rust
const PYTHON_KEYWORDS: &[&str] = &["if", "def", "return", ...];
```

This fails for three reasons:

1. **Language versions evolve.**  Python 3.10 added `match` and
   `case` as soft keywords.  Python 3.12 added `type`.  A static
   list is permanently at risk of being stale.
2. **Operators add custom languages.**  Babbleon is not
   language-specific; an operator may protect a Go shop, a Lua
   plugin system, or a domain-specific language the v2 authors
   never saw.
3. **Context-sensitive keywords.**  Shell (`if`, `then`, `else`,
   `fi`) are keywords only in certain syntactic positions.  A
   lexer-level approach misidentifies `if` inside a string literal
   as a keyword.

## The Tree-sitter solution

v2 uses **Tree-sitter** (https://tree-sitter.github.io/) as the
underlying lexer for every language it protects.  Tree-sitter
grammars are:

- Available for 100+ languages under the MIT/Apache-2 license.
- Compiled to WebAssembly and linkable as native libraries.
- Maintained by upstream communities who track language spec changes.
- Accurate at the syntactic level: they distinguish `if` as a
  keyword from `if` inside a string literal.

### How v2 uses Tree-sitter

At **scramble time** (`babbleon scramble FILE`):

1. Detect the source language from the file's shebang, extension,
   or explicit `--language` flag.
2. Load the Tree-sitter grammar for that language.
3. Run a full parse of the source file.  Tree-sitter produces a
   concrete syntax tree (CST).
4. Walk the CST.  For each leaf node:
   - If the node type is `keyword` (or a language-specific
     keyword role defined in the grammar): route the token to
     the **operator wordlist pool** for substitution.
   - If the node type is `identifier` or `name`: route to the
     **identifier wordlist pool**.
   - If the node type is whitespace, newline, indent, or dedent:
     route to the **whitespace wordlist pool**.
   - Otherwise (punctuation, string literals, numeric literals):
     route to the **decoy wordlist pool** or pass through
     verbatim based on operator config.
5. Emit the scrambled wall-of-text.

At **unscramble time** (runtime preprocessor):

1. Load the per-epoch HKDF-derived wordlists for all four pools.
2. Walk the wall-of-text token by token.
3. For each token:
   - If it matches the operator wordlist: emit the original keyword.
   - If it matches the identifier wordlist: emit the original identifier.
   - If it matches the whitespace wordlist: emit the corresponding
     whitespace character(s).
   - If it matches the decoy wordlist: discard.
   - If it matches the marker wordlist (layer 4): record chunk boundary.
4. Re-sequence chunks per layer 4 markers; emit to pipe.

The runtime preprocessor does NOT run Tree-sitter — it works
purely from the HKDF-derived wordlists, which are sufficient to
identify every token's pool at O(1) per lookup (hash set per pool).

### Grammar acquisition and pinning

v2 ships with Tree-sitter grammar WASM blobs for the baseline
language set (see below) at pinned versions.  Operators can add
custom grammars via:

```
babbleon grammar add --language mylang --wasm /path/to/mylang.wasm
```

The WASM blob is stored in the Babbleon data directory
(`/var/lib/babbleon/grammars/`) alongside a SHA-256 content hash.
The scramble pipeline refuses to use a grammar whose content hash
does not match the stored hash.  This is a supply-chain guard:
a tampered grammar could mis-classify keywords and weaken layer 2.

Grammar updates are explicit (`babbleon grammar update --language
python`) and require operator authentication.  They are logged in
the audit chain.

### Baseline language set for v2.0

| Language | Grammar source | Notes |
|---|---|---|
| Python 3.x | tree-sitter-python | Handles soft keywords (`match`, `case`, `type`) as grammar-level special cases. |
| Bash / sh | tree-sitter-bash | Handles `if`/`then`/`else`/`fi`, `for`/`do`/`done`, etc. in context. |
| C | tree-sitter-c | Handles `#include`, `#define` via the preprocessor directive node type. |
| JavaScript | tree-sitter-javascript | |
| TypeScript | tree-sitter-typescript | |
| Ruby | tree-sitter-ruby | Common on Linux servers (rbenv, etc.). |

Additional languages (Go, Lua, Perl, PHP, Java, C++) are queued
for v2.1 based on operator demand.

## Fallback: static keyword lists

For operators who cannot or will not deploy Tree-sitter (e.g.,
embedded environments, very old kernels), v2 includes a static
fallback mode per language.  Static mode is less accurate
(context-insensitive), but is better than nothing.  It is
documented as the reduced-security configuration.

`babbleon scramble --no-tree-sitter FILE` activates static mode;
the audit log records that the file was scrambled without
syntactic analysis.

## Keyword set versioning

The keyword set used to scramble a file is recorded in the file's
scramble metadata (a small binary header the preprocessor reads
before the wall-of-text).  If the grammar is updated between
scramble-time and unscramble-time, the preprocessor uses the
keyword set from the scramble metadata, not the current grammar.
This ensures existing scrambled files remain decodable after a
grammar upgrade.

Scramble metadata format:

```
[magic: 8 bytes]
[epoch: u64 le]
[language_id: u16 le]        // registry index
[grammar_content_hash: 32 bytes]  // SHA-256 of the .wasm at scramble time
[keyword_set_hash: 32 bytes]      // SHA-256 of the serialized keyword set
[payload: wall-of-text]
```

On unscramble, if the `grammar_content_hash` does not match the
currently installed grammar, the preprocessor loads the historical
keyword set from the grammar archive (stored in
`/var/lib/babbleon/grammar-archive/`).  The archive is append-
only; entries are never deleted (older scrambled files would
become undecodable).

## Open questions (decide before phase 3)

1. **Tree-sitter Rust vs WASM?**  The tree-sitter Rust crate
   links grammars as native C.  The WASM approach runs grammars
   in a sandboxed VM.  Native is faster; WASM is safer (untrusted
   grammar can't corrupt the preprocessor heap).  For v2.0,
   native with cargo-vet on the grammar sources.  WASM for custom
   operator grammars.

2. **Soft keywords (Python `match`, `case`)?**  Tree-sitter
   tree-sitter-python represents these as `identifier` nodes in
   some contexts and `keyword` nodes in others (correctly).  The
   scrambler must handle the case where the *same surface token*
   is a keyword in one position and an identifier in another — and
   the substitution must be consistent across the file.  Resolution:
   scramble-time assigns each unique (token, role) pair its own
   compound; the metadata records the dual-role mapping.

3. **String literals containing keywords?**  Tree-sitter correctly
   excludes string-literal interiors from keyword classification.
   But the scrambler currently passes string literal content through
   verbatim (it's data, not code).  That means `"if"` in a string
   stays as `"if"` in the scrambled file — potentially a
   fingerprint.  Decision: also scramble string literal content
   via the identifier pool, or leave it verbatim (simpler but
   weaker)?  Default for v2.0: leave verbatim; revisit in v2.1.
