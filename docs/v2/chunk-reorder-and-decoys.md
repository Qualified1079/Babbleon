# Chunk reorder + decoy injection — design pass 2026-06-22

Layers 4 and 5 of the v2 structural scramble (see
`structure-scrambling.md` for the conceptual sketch).  This
document is the *implementation* pass: concrete data shapes, wire
additions, edge cases, composition with the layers and
countermeasures that have landed since the original sketch
(layer 7 — `string-literal-leak.md`; C1 — `sandbox-execution-
defence.md`).

Status: design only.  No code in this commit; this doc is the
operator-review input.

## Why now

Layers 1–3 ship.  Layer 7 ships as a bench-validated prototype
(`secret_literal_layer.rs`).  Layers 4 and 5 are the next
production-code work that *composes* with what is already on disk:

- Layer 4 (chunk reorder) breaks position-based fingerprinting
  templates that survive the wall-of-words conversion of L3 — and
  it breaks "copy the scrambled source into python3" attacks that
  rely on the on-disk byte order being directly executable
  (sandbox-execution-defence.md §C3).
- Layer 5 (decoy injection) inflates the token mass an adversary
  must filter per rotation, raising the per-attempt cost the
  rotation cadence is designed to dominate.

Both layers are orthogonal to the secret-leakage failures L7 / C1
address; they harden the *outside* of the secret-touching code so
the adversary spends rotations finding code-to-attack at all.

## Scope, decisions, and out-of-scope items

| Item | Decision | Rationale |
|---|---|---|
| Granularity for L4 | **Top-level chunks only** for v2.0 | `structure-scrambling.md` §L4 already records this; statement-level reorder is O(N²) dependency analysis and yields little incremental fingerprint defence over chunk-level. |
| Marker pool source | **Separate per-epoch wordlist via dedicated HKDF purpose** | Disjointness from identifier / keyword / whitespace / decoy pools is the same invariant L3 / L2 already rely on. |
| Decoy ratio | **30% default, configurable 0.0–0.9** | Matches the original §L5 default; auto-calibrate (v2.1) per the existing roadmap. |
| Decoy content generation | **Wordlist tokens from a dedicated decoy pool** (not synthesised "fake code") | Generating syntactically-valid fake Python on the scramble side is brittle and re-introduces a fingerprint surface (the generator's grammar).  Token-level decoys mixed into the wall-of-words have no syntactic structure to fingerprint. |
| Composition with L7 | **L7 wraps secret literals at the AST level first, then L4 reorders chunks containing the wrapped calls** | L7's wrappers are call-shaped — the AST treats them as expressions, not as chunk boundaries — so L4's chunk-aware reorder passes through L7's substitutions unchanged. |
| Composition with C1 | **C1's `compute_secret(...)` call sites are call-shaped expressions** | Same composition note as L7: C1 sits below the chunk level. |
| Inter-chunk side effects | **Honoured: dependency analysis before reorder; emit a SCRAMBLER_REFUSED_CHUNK_REORDER warning when no safe permutation exists** | Side-effecting top-level statements (`logger = setup_logging()`, decorators that register classes, `MODULE_GLOBALS = {...}`) are common; silently reordering them is a correctness bug, not a fingerprint defence. |
| `if __name__ == "__main__"` | **Always pinned to last position** | Python contract; can be reordered with other chunks but tooling expects it last and we honour the convention. |
| Module-level imports | **Pinned to first position as a single ordered group** | Many libraries have import-order dependencies (`os.environ` reads before `from .config import settings`).  Within the group, individual import statements can be reordered. |
| Decorator-decorated definitions | **Decorator + definition treated as one chunk** | Splitting them is incorrect; the decorator applies to the next-following definition by Python's grammar. |
| Operator-marked anchors | **Honour `# babbleon: anchor` comments** on chunks that must NOT be reordered | Operator escape hatch for the inevitable case our dependency analysis under-detects. |

Out of scope for v2.0:

- Statement-level reorder (filed for v2.1+).
- Cross-file chunk reorder (each file is scrambled independently
  for v2.0; cross-file would need module-graph analysis that
  doesn't compose cleanly with the per-file daemon round-trip).
- "Smart" decoys that emulate the file's identifier distribution
  (filed under auto-calibration for v2.1).

## Layer 4 — chunk reorder

### Data model

```rust
pub enum Chunk {
    /// Module-level import.  All imports are pinned to the first
    /// position group; within the group they can be permuted.
    Import(SourceRange),
    /// Top-level `def f(...)` or `async def f(...)`.  Decorators
    /// that precede `f` are part of the same Chunk.
    FunctionDef { range: SourceRange, name: Identifier },
    /// Top-level `class C(...)`.  Decorators included.
    ClassDef { range: SourceRange, name: Identifier },
    /// Top-level assignment or expression statement.  These are
    /// dependency-analysed before they may be reordered.
    Statement { range: SourceRange, reads: IdentSet, writes: IdentSet },
    /// `if __name__ == "__main__":` — pinned to last position.
    MainGuard(SourceRange),
    /// Operator-marked anchor: `# babbleon: anchor`.  Reorder
    /// refuses to move this chunk; subsequent chunks may permute
    /// around it as long as dependency analysis still allows.
    Anchored(SourceRange),
}
```

`SourceRange` is a `(start_byte, end_byte)` pair against the
original file bytes.  The scrambler operates on chunk slices, not
on a re-parsed AST, so layer 4 doesn't re-serialize what L3
already produced.

### Dependency analysis (the load-bearing pass)

Before any reorder, the scrambler computes a *safe permutation
graph*:

1. Walk every `Statement` chunk; extract `reads` / `writes` via the
   same tokenizer L2 already uses for keyword detection.  No
   semantic analysis; surface-level identifier reads only.
2. Build a DAG: chunk A precedes chunk B iff `A.writes ∩ B.reads
   ≠ ∅`.
3. Topologically sort respecting the DAG; choose a *random
   linear extension* of the partial order (seeded by HKDF over the
   per-host secret + epoch + a layer-4 purpose tag).

Imports always come first (as a group), `MainGuard` always comes
last, `Anchored` chunks are fixed to their original ordinal
positions.

### Marker compound encoding

Each chunk's reordered position N is encoded by prefixing the
chunk's scrambled byte range with a *marker compound* drawn from a
per-epoch marker wordlist.  The marker wordlist is built like the
keyword / whitespace wordlists:

- HKDF purpose label: `b"v2-marker-mapping"`.
- Pool size: `MARKER_POOL_SIZE = 4096` per epoch.  Sized to handle
  the largest plausible per-file chunk count (~200) with a
  comfortable margin and enough remaining bits to encode an
  ordinal range that survives multiple decoy insertions per
  rotation.
- Each ordinal N (0..MARKER_POOL_SIZE) maps to the N-th compound
  in the per-epoch HKDF-sorted marker list.

Reserved sub-pool: ordinals `0..16` are reserved for **decoy
markers** (see §L5 below); ordinals `16..MARKER_POOL_SIZE` are
chunk-position markers.

### Preprocessor reverse pass

The preprocessor at runtime:

1. Scans the scrambled byte stream for marker compounds (greedy
   longest-prefix match against the per-epoch marker wordlist).
2. For each marker found, decodes its ordinal.  Ordinals
   `0..16` mark whole-chunk decoys → discard the bytes between
   this marker and the next.  Ordinals `≥16` mark chunk position →
   record `(ordinal, start_byte_in_scrambled, end_byte_in_scrambled)`.
3. Sorts the recorded chunks by ordinal.
4. Concatenates the chunks in sorted order; emits to the pipe the
   interpreter reads from.

The marker-recognition pass runs in O(N) over the scrambled byte
stream with a Boyer–Moore-style suffix-skip on the marker prefix
trie; the preprocessor latency budget (sub-50 ms per file per
§structure-scrambling.md "Recommended phase-3 prototype") absorbs
this pass with margin.

### Cross-pool collision risk

The marker pool and the identifier / keyword / decoy / whitespace
pools all draw from the same baseline wordlist via different HKDF
purpose tags.  A collision between a marker compound and a
non-marker compound is the same risk class L3's
`WhitespaceCompoundCollision` already accepts; we use the same
defensive check at scramble time and rotate the epoch on collision
(same operator-visible behaviour as L3).

The structure-scrambling.md Open Question §1 reserved-pool
proposal eliminates collisions across all pools by partitioning
the baseline wordlist into disjoint per-purpose slabs; that fix is
the same one L4 / L5 need, so it lands once and serves L2/L3/L4/L5
at the same time.  Filed against `docs/v2/wordlist-partition.md`
(TBD) as the unified follow-up.

## Layer 5 — decoy injection

### Inline decoys

The scrambler walks the post-L3 byte stream and inserts decoy
tokens between existing tokens at a target rate of `decoy_ratio`
(default 0.30).  Each decoy token is a compound drawn from a
dedicated *decoy wordlist*:

- HKDF purpose label: `b"v2-decoy-mapping"`.
- Pool size: 100 000 (large enough that the per-rotation token
  distribution doesn't have a Zipfian peak the attacker can
  exploit to spot the decoy class).

The preprocessor's reverse pass strips any token matching the
per-epoch decoy pool *before* the marker scan.  Strip-and-skip is
O(N) over the stream; combined with the marker scan, total
preprocessor cost remains O(N) end to end.

### Whole-chunk decoys

The scrambler optionally emits whole fake top-level chunks
(default ratio: 1 fake chunk per 3 real chunks, configurable via
`whole_chunk_decoy_ratio` 0.0..2.0).  Each whole-chunk decoy:

- Begins with a marker compound from the reserved decoy ordinal
  range (0..16).
- Contains a plausible-shaped byte run of decoy + identifier-pool
  tokens (no real keywords, no real identifiers from this file).
  The shape mimics the average chunk shape in the file (median
  token count, ±20% jitter) so an attacker can't spot decoy
  chunks by length alone.

The preprocessor strips whole-chunk decoys before the marker-sort
pass: any chunk whose lead marker decodes to an ordinal in
`0..16` is dropped, *not* sorted into the output stream.

### Performance budget

Per `structure-scrambling.md` §L5 cost note: at 30% inline-decoy
ratio plus the default whole-chunk decoy rate, the preprocessor
runtime is ~1.4× zero-decoy.  At 70% inline + heavy whole-chunk
decoy, ~3×.  We benchmark before committing the default by
extending `tools/preprocessor-benchmark/` with decoy-injection
configurations once the implementation lands.

### Generation: avoiding the decoy-shape fingerprint

If decoys are obviously distinguishable from live code (different
token-length distribution, different N-gram frequencies, missing
the keyword-compound population that real code emits), the
attacker filters them out for free.  Two guards:

1. **Same wordlist family.**  Decoy tokens come from the same
   baseline wordlist as identifier / marker / whitespace tokens;
   surface byte distribution is identical.
2. **Keyword-compound salting.**  Whole-chunk decoys include
   keyword compounds at the file's average keyword-density rate
   (sampled from the post-L2 output).  An attacker who tries to
   filter "no keywords → decoy" filters out real-code chunks that
   genuinely have no Python keywords (e.g. constant assignments at
   module scope).

The second guard is the load-bearing one and the source of the
biggest implementation risk: a sloppy decoy generator that emits
keyword-free chunks gives the attacker a free filter.  Tests must
cover the keyword-density invariant.

## Composition

### With L2 (keyword scramble)

Layer 4 runs *after* L2 in the scramble pipeline.  Chunks contain
already-scrambled keywords; the chunk-extraction pass walks the
L1+L2-scrambled byte stream, not the original source, so chunk
boundaries are detected at the token level (post-keyword-scramble
chunks still have recognisable structure — `def` is a marker the
L2 pass kept track of in the original AST, and the chunker
records its pre-scramble byte positions).

Concretely: the scramble pipeline is

```
original source
   → L1 identifier scramble (token-level rename)
   → L2 keyword scramble (token-level substitution)
   → L4 chunker (uses pre-scramble AST boundaries; produces Chunk[])
   → L4 reorder (permute Chunk[] per HKDF-sorted ordinals)
   → L5 whole-chunk decoy injection
   → L3 whitespace-as-words conversion (concatenated chunks)
   → L5 inline-decoy injection
   → scrambled bytes on disk
```

The unscramble pipeline reverses it:

```
scrambled bytes
   → L5 inline-decoy strip (preprocessor decoy-pool filter)
   → L3 whitespace-as-words → token stream
   → L5 whole-chunk decoy strip (marker-ordinal 0..16 filter)
   → L4 chunk-sort (marker-ordinal ≥16 collation)
   → L2 unscramble (keyword reverse-lookup)
   → L1 unscramble (identifier reverse-lookup)
   → unscrambled source → pipe to interpreter
```

L1 and L2 reverse passes are token-level and order-independent;
the L4 sort happens before them because the marker compounds are
embedded *between* chunks (not inside them).

### With L7 (secret literal substitution)

Layer 7 rewrites `"silver7"` → `secret("password-1")` at AST
build time.  The substitution lives inside a chunk; L4's
chunker treats it as ordinary chunk content.  No L4 / L7
interaction at the chunk boundary.

Performance note: L7 lookups go through the daemon at runtime; if
the chunk containing the L7 call sits at the end of the reorder
output, the daemon round-trip starts later in the program lifetime.
This is a property of L4 reordering execution order, not a bug —
the operator marks any L7 call that needs to execute early via
the `# babbleon: anchor` mechanism.

### With C1 (runtime secret helper)

Same composition note as L7.  `babbleon.runtime.compute_secret(...)`
calls live inside chunks; L4 reorder doesn't touch them.

### With existing layers 8–12 (filed but not implemented)

Per `obfuscation-landscape.md`, layers 8 (opaque predicates),
9 (constant unfolding), 11 (defensive prompt injection), and
12 (charset tricks) are all token-level or expression-level.  They
sit inside chunks and compose with L4 the same way L2 and L7 do.
Layer 6 (segment reversal) operates on byte ranges that the L3
output produces; L4 places those byte ranges into per-chunk
slots, so L6's reverse pass at the preprocessor must run
chunk-locally — same fix L7 already needs.

## Wire-format additions

The daemon needs to serve two more per-epoch pools so the
operator CLI can drive scramble / unscramble:

| Request | Response payload | Notes |
|---|---|---|
| `GetMarkerCompounds` | `{epoch, compounds: [String; MARKER_POOL_SIZE]}` | The 4096-entry pool is bigger than the array-on-stack appetite of the existing `WhitespaceCompounds` / `KeywordCompounds` patterns; ship as a JSON array on the wire and as `Box<Vec<String>>` in Rust to keep the `Response` enum small. |
| `GetDecoyCompounds` | `{epoch, compounds: [String; DECOY_POOL_SIZE]}` | Same shape as marker; 100 000 entries means ~3 MB on the wire per request.  Bigger than the current `MAX_REQUEST_BYTES`-class budget for the request side; response side is bounded by the activated-table cap (16 MiB) so well within. |

Both pools rotate on epoch change.  CLI consumers cache the
per-epoch pool locally for the rotation lifetime; daemon refuses
the request when Locked (same gate the existing
`GetWhitespaceCompounds` / `GetKeywordCompounds` requests use).

## Implementation sequence

Smallest reviewable units, in order:

1. **Marker wordlist + decoy wordlist** in
   `v2-babbleon-preprocessor`: HKDF derivation, pool size
   constants, `from_compounds` constructors, unit tests.
   Pattern-match against the existing
   `KeywordWordlist` / `WhitespaceWordlist`.  ~400 LOC + ~25 tests.
2. **Chunker** in `v2-babbleon-preprocessor`: AST walk producing
   `Chunk[]`, dependency analyser producing the precedence DAG,
   topological sort producing a random linear extension.  ~600
   LOC + ~30 tests covering the edge-case matrix above.
3. **L4 scrambler / unscrambler**: emit chunks with marker
   prefixes; preprocessor reverse pass sorts by ordinal.  ~400
   LOC + ~15 tests.
4. **L5 decoy scrambler / stripper**: inline and whole-chunk;
   reverse pass strips both.  ~300 LOC + ~15 tests.
5. **Daemon wire surface**: `GetMarkerCompounds` and
   `GetDecoyCompounds` requests, mirroring this session's
   keyword-compounds wiring.  ~300 LOC + ~10 tests.
6. **CLI integration**: `babbleon scramble FILE` and
   `babbleon unscramble FILE` issue the new requests, build the
   pools locally, drive the full L1+L2+L3+L4+L5 pipeline.  ~250
   LOC + ~10 tests.
7. **Bench challenge**: extend
   `v2-babbleon-resilience-bench` with a `chunk-reordered`
   challenge to measure the crack-fraction shift L4 produces.
   ~100 LOC.

Total: ~2 350 LOC + ~105 tests, across ~6 PR-sized commits.  Each
commit follows the security-baseline-15 checklist
(`docs/v2/security-baseline.md`); each commit ends with a HANDOFF
entry recording test counts + clippy-pedantic status.

## Test strategy

Property tests already cover the L1/L2/L3 scramble↔unscramble
round trip on arbitrary inputs.  L4 / L5 add:

- **Chunker correctness**: every chunk's `SourceRange` is a valid
  slice; concatenation of chunks in original order reconstructs
  the input file byte-for-byte.
- **Dependency-analysis safety**: for every input file with
  side-effecting top-level statements, the chosen permutation
  preserves the partial order `writes-before-reads`.
- **Round-trip**: `unscramble(scramble(source, secret, epoch))
  == source` for arbitrary valid Python sources, with L4 + L5
  active.  This is the load-bearing property — if it fails,
  user code breaks at runtime.
- **Reorder invariant**: across rotations, the chunk order in the
  scrambled output changes.  (Same shape as the existing
  `rotation_changes_every_compound` test for L2 / L3.)
- **Decoy strip invariant**: for any scrambled output, applying
  the preprocessor's decoy-strip pass and the marker-sort pass
  yields exactly the live-code chunks in their original order.
  Property over arbitrary `decoy_ratio` and
  `whole_chunk_decoy_ratio` values.
- **Keyword-density invariant on decoys**: the mean and variance
  of keyword-compound frequency in whole-chunk decoys matches the
  same statistic on live-code chunks, within a configurable
  tolerance.  This is the only test in the suite that's purely
  about adversary cost rather than correctness; it gates the
  "decoy generator is not trivially fingerprintable" claim.
- **Adversarial bench**: re-run the existing challenges with L4
  and L5 active.  Expected: crack-fraction drops to near-zero on
  position-fingerprintable challenges; on the `computed-secret`
  challenge (which already cracks via execution under L3-only) the
  shift is whatever C3 (sandbox-execution-defence §C3) buys —
  not zero, but measurably lower than L3-only.

## Open questions

1. **Marker pool size.**  4096 is back-of-envelope.  An
   information-theoretic derivation parametric in chunk count and
   decoy ratio (see TODO.md §"Algorithmic derivation of per-role
   wordlist pool sizes") would replace the constant.  Filed for
   v2.1 alongside the existing wordlist-sizing TODO.
2. **Per-file marker rotation.**  Today every file in a project
   uses the same per-epoch marker wordlist.  Per-file derivation
   (HKDF over `(secret, epoch, file_path_hash)`) would mean a
   leaked marker pool for one file doesn't help an attacker on
   another file.  Cost: per-file derivation on every preprocessor
   invocation.  Decide before phase-4 ship.
3. **Decoy chunk generation determinism.**  Decoy content should
   be deterministic for `(secret, epoch, file_path, chunk_slot)`
   so that an adversary who saves the scrambled file and replays
   it next rotation sees the same decoys.  Otherwise the decoy
   set itself becomes a rotation-window leak.  Decoy seed
   derivation matters; lock it in alongside the marker pool
   derivation.
4. **Anchor comment syntax stability.**  `# babbleon: anchor` is
   a comment; L3 turns comments into byte-runs the preprocessor
   has to recognise.  Today's L3 doesn't special-case Python
   comments at all (the MVP tokenizer treats them as
   `Token::Word` runs).  Need either a comment-aware tokenizer
   bump or a different anchor mechanism (operator config file,
   decorator-style annotation).  Filed.
5. **Cross-file chunk reorder.**  Out of scope for v2.0 per the
   decision table above, but worth a follow-up note before v3:
   would whole-module reorder buy more than per-file reorder?
   Likely yes for fingerprinting; cost is module-graph analysis,
   which interacts badly with dynamic imports.

## What this design does NOT solve

Honesty checklist:

- **Adversary who runs the preprocessor under the same
  trusted-tier privileges** — they get the unscrambled source by
  design.  L4 / L5 raise the cost to an adversary who only has
  read access to the scrambled source, not to one who has
  trusted-tier execution.
- **AST-aware adversary who reconstructs the original chunk order
  from semantic dependencies.**  If chunks are visibly
  interdependent (function A calls function B), an attacker can
  topologically sort the call graph and recover *one* valid order
  even without the marker compounds.  L4's defence is "one valid
  order out of many" — when there are few semantic dependencies,
  L4 buys more; when there are many, L4 buys less.  The
  bench-side measurement is the honest answer.
- **Decoys that interact with import-time side effects.**  Whole-
  chunk decoys are bytes the preprocessor strips before
  emission; they never execute, so there is no import-time-side-
  effect risk.  But a decoy generator that emits chunks whose
  byte content collides with a real import statement (random
  pool draw lands on `import os`) is observably decoy-shaped to
  an adversary who can compare the strip-result to the on-disk
  bytes.  Mitigation: decoy generation rejects draws that match
  any real-keyword compound for the current epoch.

## Cross-references

- `docs/v2/structure-scrambling.md` — original §L4 / §L5
  conceptual sketch.
- `docs/v2/string-literal-leak.md` — L7 design (composes
  inside-chunk).
- `docs/v2/sandbox-execution-defence.md` — C1 design (also
  inside-chunk) + C3 cross-reference (chunk reorder).
- `docs/v2/obfuscation-landscape.md` — layers 6 / 8 / 9 / 11 /
  12 composition notes.
- `crates/v2-babbleon-preprocessor/src/keyword_wordlist.rs` —
  pattern to follow for marker / decoy wordlists.
- `crates/v2-babbleon-daemon-protocol/src/protocol.rs` — pattern
  to follow for the two new requests / responses.
