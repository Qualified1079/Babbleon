# Real Python parser feasibility — `rustpython-parser` vs Tree-sitter

Status: **research only, no code changed**.  This is decision support
for the operator call `HANDOFF.md` and `TODO.md`'s Layer 7/8/10
entries have been flagging since 2026-07-04 ("blocked on either a
real parser or an operator decision"); it does not make that call.

## The problem this addresses

Three open items share one root cause — the MVP `python_tokenizer`
is a whitespace/character scanner with no concept of Python
statement or expression structure:

- **Layer 7** (control-flow flattening) and **Layer 8** (opaque
  predicates) both need to insert new code at a location guaranteed
  safe by *Python's* grammar (not "depth-0 by indent-balance,"
  which is what L4/L5 use today). `TODO.md`'s Layer 8 entry has a
  reproduced example: `chunk_reorder`/`decoy_injection`'s depth-0
  heuristic lands a decoy between a decorator and its target in
  ~25% of 5000-epoch draws — harmless for L5 (fully stripped before
  execution) but would be a `SyntaxError` generator for any layer
  that has to leave its insertion in the *executed* program.
- **MVP_LIMITATIONS #3** (`python_tokenizer.rs`'s own module doc):
  "operators are not split from identifiers" — `f(22)` tokenizes as
  one `Word`, not `f`, `(`, `22`, `)`, which is why L9 (constant
  unfolding) only handles whitespace-delimited bare integers, not
  `f(22)`.

Both are the same wall: no AST.

## What was actually evaluated (this session, in a scratch crate outside the repo, nothing committed)

Two candidates were pulled from crates.io and exercised, not just
read about:

### `rustpython-parser` 0.4.0

- **Pure Rust, no C toolchain at build time.** `cargo tree` from a
  throwaway crate showed 46 total transitive dependencies, all
  Rust crates (`itertools`, `phf`, `malachite-bigint` for Python's
  arbitrary-precision ints, `unic-*` for Unicode identifier
  classification, `lalrpop-util`, ...). No `cc`/`bindgen` build
  dependency anywhere in the tree.
- **License: MIT.** Every crate in the dependency tree checked
  (`rustpython-parser`, `rustpython-ast`, `rustpython-parser-core`,
  `rustpython-parser-vendored`) declares `license = "MIT"` in its
  own `Cargo.toml` — on `deny.toml`'s allow list already, no policy
  change needed.
- **MSRV 1.72.1**, edition 2021 — under the workspace's
  `rust-version = "1.75"` floor (`Cargo.toml` line 33). No MSRV
  bump needed.
- **Builds clean** under this sandbox's toolchain (`rustc 1.94.1`)
  in ~20s cold.
- **Verified, not assumed, against the exact two cases above:**
  - `ast::Suite::parse` on `"@staticmethod\n@app.route(\"/x\")\ndef
    f():\n    return 1\n"` produced a `StmtFunctionDef` node with an
    explicit `decorator_list: [Name(staticmethod), Call(app.route(...))]`
    field, each with its own byte `range`. This is exactly the
    "decorator-target binding" information the depth-0 heuristic
    lacks — a real parser turns "don't insert between a decorator
    and its target" from a 25%-failure-rate guess into a direct
    `decorator_list.is_empty()` / statement-boundary check.
  - `ast::Suite::parse` on a source string combining `match`/`case`,
    `async def`/`async with`, a walrus operator (`z := 3`), and a
    nested f-string with a format-spec (`f"{b!r:>{width}}"`) parsed
    without error — current Python surface syntax is covered, not
    just Python 2-era grammar.

### `tree-sitter` 0.26.10 + `tree-sitter-python` 0.25.0

Also pulled and added to the same scratch crate for a direct
comparison, since `docs/v2/dynamic-keywords.md` already picked
Tree-sitter as the project's stated multi-language design (for
Layer 2 keyword extraction — a decision that was later superseded in
practice: the Phase-0 "open research" item that shipped
`identifier_scrambler.rs` deliberately went the other way, deleting
`python_keywords.rs`/`python_operators.rs` in favor of a fully
language-agnostic whitespace-delimited scrambler that needs no
per-language grammar at all — see `TODO.md`'s Phase 0 "Dynamic /
language-agnostic keyword extraction" entry).

- `cargo add` pulls in `cc` as a build-dependency — `tree-sitter-python`
  ships its grammar as generated C source (`src/parser.c`) compiled
  by a `build.rs` at build time. That's a real build-environment
  requirement (a working C compiler) neither `rustpython-parser` nor
  any other v2 crate currently needs.
- Confirmed a larger transitive footprint for the same probe crate:
  20 additional packages beyond `tree-sitter`/`tree-sitter-python`
  themselves (`regex`, `serde`, `serde_json`, `indexmap`, ...) pulled
  in by `tree-sitter`'s query engine, which this project's use case
  (walk one already-known grammar's tree, no dynamic query language)
  would not exercise.
- Multi-language reach (100+ grammars) is Tree-sitter's real
  advantage over `rustpython-parser` — but the shipped preprocessor
  is Python-only today (`python_tokenizer.rs`; no Bash/C/JS tokenizer
  exists in `crates/v2-babbleon-preprocessor/src/`), so that
  advantage is currently unused. If/when the preprocessor grows a
  second language, this tradeoff should be re-evaluated — Tree-sitter
  amortizes across languages in a way `rustpython-parser` (Python-only
  by construction) cannot.

## Why this is operator-gated, not an autonomous pickup

Consistent with every other Layer 7/8/10 entry in `TODO.md` and
`HANDOFF.md`: swapping the tokenizer is not a self-contained bugfix
like the 2026-07-09 triple-quoted-string fix was. It's a new
mandatory dependency (`rustpython-parser` pulls 46 transitive
crates into `v2-babbleon-preprocessor`, a crate that today has
exactly one non-workspace dependency, `thiserror`) plus a rewrite of
`python_tokenizer.rs`'s `Word`/`Newline`/indent-token IR that every
downstream layer (L2 through L12, `file_format.rs`'s wire format,
the daemon protocol's `GetTokenMapping`) is built against. That is
squarely the kind of architecture-scale, dependency-adding decision
`CLAUDE.md` §4 reserves for the operator ("no new unconditional
default-workspace deps" without review), not something a session
should decide unilaterally by importing it and wiring it through.

## Recommendation, if/when the operator picks this up

`rustpython-parser` is the better default candidate for the
Python-only, no-C-toolchain, MIT-license-compatible constraints this
project already operates under — **provided the migration is scoped
as "swap `python_tokenizer.rs`'s IR for an AST-derived one," not "add
Tree-sitter's multi-language machinery for a single-language
preprocessor."** Re-open the Tree-sitter path specifically if a
second target language is ever prioritized, since that is the one
axis `rustpython-parser` cannot cover.

If approved, this single swap is a genuine multiplier per the
2026-07-04 HANDOFF entry's own framing: Layer 7, Layer 8, and a
correct "insert new top-level statement safely" primitive (needed by
any future layer that leaves code in the *executed* program, not
just fully-restored-before-execution ones like L4/L5/L9) all become
buildable off the same AST, not three separate unblocks.
