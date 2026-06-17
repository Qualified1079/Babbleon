# Structure-level scrambling — v2 design

The technical heart of Babbleon v2.  This document captures the
analysis behind the decision to move beyond v1's identifier-only
scramble, and lays out the layered mechanism v2 will implement.

## The problem v2 solves

Operator tested several models against the current v1 scramble:

- None could crack the scramble *blind* (given only the scrambled
  source).
- All cracked it *instantly* when shown the original alongside.

This is the actual threat once Babbleon becomes well-known.  An
attacker model doesn't need to reason about the scramble; it has
host-class structural templates cached offline (Ubuntu server,
RHEL desktop, Debian appliance, ...) and pattern-matches the
*shape* of the scrambled file against those templates to locate
exploit-insertion points.

Example: a model that knows the target is an Ubuntu host running
nginx can identify `nginx.conf` by its line-count, indent-pattern,
and brace-shape without ever resolving the scrambled identifier
that points at `nginx`.  Once located, the model inserts a
prepared scrambled-name into the configuration file at the
correct slot and the exploit lands — even though it never decoded
the scramble at all.

v1 defeats *lexical* recognition.  It does not defeat *structural*
recognition.  Once Babbleon is publicly known, the structure
attack matters more than the identifier attack.

## The five composable layers of v2 scrambling

Each layer can be enabled independently; full v2 enables all five.
The layers are listed in increasing order of engineering cost.

### Layer 1 — identifier scramble (v1 already does this)

`curl` becomes `riverstoneanvilfreckle`.  Per-host bijective
mapping seeded by `HKDF(host_secret, epoch, "identifier")`.
Wordlist compounds drawn from a 370k-word English list (v1) or
multi-language list (v2 — see layer 6 below).

**What this defeats:** cached-exploit attackers who pattern-match
on canonical names.

**What this does NOT defeat:** structural fingerprinters, models
shown the original.

### Layer 2 — operator scramble (NEW in v2)

Reserved keywords (`if`, `def`, `return`, `class`, `import`,
`for`, `while`, `try`, `except`, `with`, `as`, `from`, `lambda`,
`yield`, ...) become wordlist compounds drawn from a separate
*keyword wordlist*.  The runtime preprocessor un-substitutes
before the interpreter sees the source.

**Per-language scope:**

- Python keywords (~35): the easy case; the lexer is generous
  about identifier shape.
- Shell built-ins (`if`/`then`/`else`/`fi`, `for`/`do`/`done`,
  `case`/`esac`): harder because shell syntax is whitespace-
  sensitive and partial.
- C / C++ reserved words: requires a preprocessor stage before
  the C preprocessor.
- JavaScript / TypeScript: similar to Python.
- Rust: skip — Rust source is for development, not for distribution
  on a Babbleon-protected host.

**Cost:** the preprocessor has to know the host's source-language
keyword sets.  Mitigation: ship a built-in set for the top languages
(Python, sh, bash, C); allow operators to register custom keyword
sets per file extension.

**What this defeats:** "this is Python source" recognition.  A
model that cannot resolve `def`, `return`, or `import` cannot
identify the file as a Python module.

### Layer 3 — whitespace as words (THE big idea)

Replace `\n`, ` ` (single space), `\t`, indent-block-open, and
indent-block-close with wordlist compounds drawn from a *whitespace
wordlist*.  Source code becomes one continuous wall of text.  No
visible line breaks, no visible indentation, no visible block
structure.

**Example (pseudocode for clarity; real v2 output is all-lowercase
no-separator compounds):**

Before:
```python
def hello(name):
    if name:
        print("hi", name)
    return name
```

After (each block-token is a compound; spaces shown here only to
guide the eye — v2 output has no spaces):
```
{def-compound} {hello-compound} {open-compound} {name-compound} {close-compound}
{colon-compound} {indent-open-compound}
{if-compound} {name-compound} {colon-compound} {indent-open-compound}
{print-compound} {open-compound} {hi-compound} {comma-compound} {name-compound} {close-compound}
{indent-close-compound}
{return-compound} {name-compound}
{indent-close-compound}
```

In real v2, the file is one continuous text blob.  Open it in
`cat`, you see a wall of words.  Open it in an editor that lacks
the v2 plugin, same.

**The runtime preprocessor** is what makes this work.  It:

1. Reads the scrambled source from disk (or stdin).
2. Identifies whitespace tokens via the per-epoch whitespace
   wordlist.
3. Identifies operator tokens via the per-epoch keyword wordlist.
4. Identifies identifier tokens via the per-epoch identifier
   wordlist.
5. Re-emits unscrambled source to a pipe.
6. The interpreter reads from the pipe.  Unscrambled source is
   NEVER written to disk.

**What this defeats:** shape fingerprinting.  No visible line
boundaries, no visible indentation, no visible block structure.
The attacker model sees a wall of words and has nothing to
position-match against.

**Cost:** every tool that reads source code by `read()`-ing the
file (cat, less, grep, ag, ripgrep, every editor) sees garbage.
Mitigation: editor plugins, plus a CLI utility
`babbleon unscramble FILE` that emits the unscrambled source to
stdout (gated to the trusted tier; refuses to run in untrusted).

### Layer 4 — chunk-level code reorder with word-tag markers

Top-level blocks (function defs, class defs, module-level imports
and statements) are permuted at scramble time.  Each block carries
an **execution-order word-tag** — a wordlist compound drawn from a
dedicated *marker wordlist* pool — that the runtime preprocessor
uses to reconstruct the original execution order before emission.

**Granularity: top-level chunks only.**  Python (and most
languages) tolerate any top-level definition order as long as
references resolve before use.  Reordering inside a function
changes semantics; reordering top-level chunks does not.
Statement-level reorder is NOT implemented — the runtime cost
grows roughly as O(N²) for dependency analysis inside a function
body, and the marginal fingerprint benefit over chunk-level is
small.

**The word-tag mechanism:**

Each chunk begins with a compound token drawn from the per-epoch
marker wordlist.  The compound encodes an ordinal N via an
HKDF-derived sub-permutation of the marker wordlist: to encode
position N, the scrambler selects the N-th compound in the
HKDF-sorted marker list.  The preprocessor reverses this:

1. Scan the wall-of-text for any compound that matches the marker
   wordlist.
2. Decode the ordinal N from the compound's position in the
   HKDF-sorted marker list.
3. Assign the following tokens (up to the next marker) to chunk N.
4. Sort all chunks by N; concatenate; emit.

The marker compounds are indistinguishable from any other
wordlist compound to an observer without the epoch key.  The
attacker must recover the per-epoch HKDF sub-key for the marker
pool before they can identify chunk boundaries — which requires
knowing the host secret.

**What this defeats:** position-based fingerprinting.  Templates
that assume "imports come first, then helpers, then main" no
longer work.  The attacker must parse the wall-of-text, identify
markers, decode ordinals, and reconstruct chunk order — all of
which requires the epoch key.

**Performance profile:** chunk sort is O(C log C) where C is
the number of top-level chunks (typically 10–200 per file).
Negligible.

**Cost:** the preprocessor must topologically sort the marked
blocks before emitting.  Trivial; one pass.

### Layer 5 — junk decoy injection

The scrambler injects wordlist tokens (and whole fake statements)
that the runtime preprocessor strips before emission.  Target:
~70% noise, ~30% live code by token count.

**Two flavours:**

- **Inline decoys** — wordlist tokens inserted between real
  tokens.  Marked via a per-epoch *decoy wordlist*; the
  preprocessor strips any token matching that decoy pool.  Cheap
  to insert, cheap to strip.
- **Whole-chunk decoys** — entire fake top-level blocks (a fake
  function-body-shaped blob) that the preprocessor recognises via
  a marker compound (same word-tag pool as layer 4, with a
  reserved "null-ordinal" convention) and skips.  More expensive
  but defeats attackers that try to parse before stripping.

**Default decoy ratio: 30%.**  This is the out-of-box default.
Configurable via `decoy_ratio` (float 0.0–0.9) in the operator
config.  Rationale: 70% decoy is the maximum-security target but
triples preprocessor latency; 30% halves the live-code fraction
visible to an unarmed attacker at ~1.4× latency cost.  The
right ratio depends on the hardware and the operator's performance
budget.

**Auto-calibration** (v2.1, not v2.0): on first install or
`babbleon calibrate`, the preprocessor runs a benchmark loop,
measures per-file latency at several `decoy_ratio` steps, and
proposes the highest ratio that keeps p99 latency under the
operator's configured budget.  The operator accepts or overrides.

**What this defeats:** the rotation-window attacker.  At v1's
measured warm-rotation cost (24 ms at N=100), the attacker has
~250 ms total to: locate live code, adapt an exploit, submit it.
With 30% decoy, "locate live code" requires a filtering pass over
1.4× more tokens per attempt; the rotation window closes before
the attack adapts.  At 70% decoy, "locate live code" is a 3×
more expensive parsing task per attempt.

**Cost:** strip-on-read is O(N) over input; preprocessor latency
scales with decoy ratio.  At 30% decoy, expect ~1.4× preprocessor
runtime vs zero-decoy.  At 70% decoy, ~3×.  Measure before
shipping.

**What v2 does NOT do:** inject fake error messages, fake help
text, or spoofed version strings.  "Deception output" (fake
`--help` banners, fake `which` responses) was considered and
rejected.  It creates compatibility nightmares with monitoring
tools, EDR products, package managers, container runtimes, and
automation scripts that parse tool output.  The null banner (exit
127, no stdout) is the correct untrusted-tier response.
See `docs/v2/gui-design.md` for the trust-grant mechanism that
handles legitimate tools that need to run in the trusted tier.

### Layer 6 — multi-language wordlists

Cycle the wordlist through multiple natural languages per epoch.
EN, ES, FR, DE, JA, ZH, AR, RU.  Combined unique-word count:
~1.5M+ across all eight.

**Effect on frontier models:** marginal.  Frontier models reason
in semantic space; the language of the surface tokens is mostly
post-tokenizer.

**Effect on smaller models:** measurable.  Smaller models trained
on English-only corpora tokenize non-English worse (more bytes
per token), fall back to UNK more often, and have weaker semantic
embedding for non-EN tokens.  Tokenizer benchmark already showed
~7% per-token-cost inflation for compound names in English; multi-
language plausibly pushes that into the 15-30% range for smaller
models.  Hypothesis, not measurement; v2 will measure with the
existing tokenizer-benchmark harness.

**Cost:** maintaining multilingual wordlists.  All are public-
domain or permissive-licensed; no new infrastructure.

## The runtime preprocessor — load-bearing component

Layers 2-5 all require a preprocessor that runs between the
scrambled source on disk and the interpreter's `read()`.  This
preprocessor is the v2 component that earns the most security
review.

### Trust placement

The preprocessor runs **only in the trusted tier**.  An untrusted-
tier process that tries to execute a scrambled file directly hits
the OS exec, which fails because the file is not a valid
interpreter input.  An untrusted-tier process that tries to
invoke the preprocessor hits the trust-tier check (mnt-NS inode
comparison, same mechanism as v1's wrapper) and the preprocessor
refuses.

### No-disk guarantee

The preprocessor NEVER writes unscrambled source to disk.  It
reads the scrambled file, unscrambles in-memory, and writes the
unscrambled bytes to a `pipe(2)` whose read end is `dup2`'d to
the interpreter's stdin (or to a memfd_create file the
interpreter reads).  The unscrambled bytes live only in the
preprocessor's heap and the interpreter's heap; both are
hardening targets.

### Same hardening as the daemon

The preprocessor calls `harden_for_secrets()` at startup:
`PR_SET_DUMPABLE = 0`, `RLIMIT_CORE = 0`, `mlockall(CURRENT |
FUTURE)`.  Holds its wordlists in `Zeroizing<Vec<...>>`.  Wipes
the unscramble buffer between files.

### Its own seccomp profile

The preprocessor needs: `read`, `write`, `openat`, `close`,
`mmap` (for wordlist memmap), `mprotect`, `brk`, `execve` (to
spawn the interpreter), `pipe2`, `dup3`, plus the usual signal-
handling and exit syscalls.  It does NOT need: `socket`, `bind`,
`connect`, `accept`, `mount`, `unshare`, `ptrace`, `bpf`,
`process_vm_readv`, `kcmp`.  Filter denies all of the second set.

### Attack surface and mitigations

| Attack | Mitigation |
|---|---|
| Untrusted process invokes the preprocessor and reads its stdout | Trust-tier check refuses; preprocessor exits 1 without unscrambling. |
| Race to read the unscrambled pipe | The pipe's read end is `dup2`'d directly to the interpreter; no FD-table window. |
| Side-channel reading the preprocessor's heap | `mlockall` keeps pages in RAM; ptrace blocked by seccomp; same-uid attackers blocked by Yama `ptrace_scope=2`. |
| Memory disclosure via a crash | `PR_SET_DUMPABLE = 0` + `RLIMIT_CORE = 0` refuses core dumps. |
| Preprocessor itself is compromised | Preprocessor is a small static Rust binary; minimal dependency tree; cargo-vet, miri, fuzz. |

## Composition picture

With all five layers enabled plus multilingual wordlists, the
attacker model trying to insert an exploit during a rotation
window sees:

- A wall of text with no visible structure.
- Tokens drawn from 8+ natural languages.
- ~70% of tokens are decoys that get stripped.
- Of the ~30% live code, identifiers AND keywords AND whitespace
  are all scrambled.
- Block-level execution order is permuted.
- Rotation closes the entire mapping in ~250 ms.

The attacker has to: identify which tokens are decoys (per-epoch
mapping), identify which tokens are whitespace (per-epoch
whitespace mapping), identify which tokens are keywords (per-
epoch keyword mapping), parse the resulting source enough to
determine block order, then insert an exploit token that maps to
the desired real identifier under the current epoch's identifier
mapping.

All within ~250 ms.

## Open questions

These are explicit "decide before phase 3" items, not punted
items:

1. **Branch vs subtree?** Does v2 develop on a separate branch
   (`v2-main`) with v1 frozen on `main`, or in a `crates/v2-*`
   subtree of `main` with both versions buildable side-by-side?
   The subtree approach is friendlier for incremental migration
   testing; the branch approach is cleaner for "the public
   product is v2".  Open.
2. **Preprocessor binary vs library?**  Standalone binary
   (`babbleon-preprocessor SCRAMBLED_FILE -- python3 ARGS`) or
   library linked into a `babbleon-run` launcher?  Standalone is
   easier to seccomp-profile; library is faster (no exec per
   run).  Probably standalone for v2.0, library for v2.1.
3. **What's the file-extension convention for scrambled source?**
   Does `app.py` stay `.py` (any tool opening it sees garbage but
   the OS still routes it to the Python interpreter) or become
   `app.py.babbleon` (clearer to operators, breaks every script
   that hardcodes `.py`)?  Probably keep `.py` and rely on the
   shebang line being scrambled too.
4. **How does v2 interact with virtualenvs / containers?**  If
   the user's app runs in a `venv`, the preprocessor has to be
   inside the venv too, or it has to be before-venv in the
   PATH.  Operator docs question.
5. **Editor plugin landscape.**  VS Code first?  Vim/Emacs as
   second-class?  Or none — make `babbleon unscramble` the
   universal "show me what this is" tool and let editors stay
   ignorant.

## What this design does NOT solve

In the interest of honesty:

- **The L1/L2/L3 limitations from v1's threat model.**
  Built-in syscall bypass, BYOE static payloads, and the
  `/proc/self/maps` libc leak all still apply.  v2 does not
  obfuscate libc or block raw syscalls; those remain
  composed-with-other-defences items.
- **Compiled binaries.**  v2's structural scrambling targets
  *source code*.  ELF binaries continue to use v1's banner-
  spoofing wrapper.  Operators with bring-your-own static
  payloads still bypass.
- **The preprocessor itself being a target.**  If an attacker can
  read the preprocessor's memory, they read the unscramble
  mappings for the current epoch.  Mitigations listed above are
  best-effort; a kernel CVE in `ptrace_scope` or `mlockall`
  enforcement reopens this.

## Recommended phase-3 prototype

Smallest experiment that proves the design:

1. Ship the runtime preprocessor as a standalone Rust binary.
2. Implement layer 3 only (whitespace-as-words) for Python files.
3. Add a CLI `babbleon scramble FILE` that produces a scrambled
   version on stdout, and `babbleon unscramble FILE` that reverses
   it (trust-tier only).
4. Wrap `python3` with a babbleon shim that runs scrambled `.py`
   files through the preprocessor + interpreter pipeline.
5. Measure the preprocessor latency on the existing
   `rotation-benchmark` hardware to confirm sub-50 ms per file.
6. Run the operator's adversarial-LLM test (the one that defeated
   v1 when shown the original) against the layer-3-only output.
   Record the result.

If layer 3 alone moves the adversarial-LLM test from "defeats
trivially" to "defeats with effort", phase 3 adds layers 2, 4, 5
incrementally.

If layer 3 alone does NOT defeat the test, escalate to layers 2+3
together and re-measure before continuing.
