# Binary self-identification — measured, and what it costs us

Filed: 2026-10-14.  Measured on this host, this branch.

## TL;DR

**Renaming a compiled third-party binary denies an adversary
almost nothing.**  Five of six renamed GNU/curl tools identify
themselves in a single `--version` sweep — six commands, no
inference, no probing strategy.  `curl`, the highest-value tool on
the list, leaks through three independent channels at once.

This does **not** touch the denial thesis for preprocessed source
(L2-L12 operate on source, and nothing here measures them).  It
retires one specific claim: that the untrusted tier cannot
recover the tool inventory.  It can, trivially.

## What was measured

Six real binaries copied into a directory and renamed to compound
names drawn from the production 369 652-word wordlist
(`crates/v2-babbleon-scramble/wordlist/words.txt`), exactly as a
per-host mapping would rename them.  Nothing else was changed:
the files are byte-identical to `/usr/bin/<tool>` apart from their
name.  That is what a Babbleon host looks like today for a
compiled tool — the rename changes the filename and leaves every
byte inside untouched.

Then: one loop invoking each with `--version`.

| Renamed to | `--version` first line | Identified |
|---|---|---|
| `resack_unluck` | `curl 8.5.0 (x86_64-pc-linux-gnu) libcurl/8.5.0 OpenSSL/3.0.1` | yes — and names its TLS stack |
| `dulias_tritons` | `tar (GNU tar) 1.35` | yes |
| `latish_grip` | `sort (GNU coreutils) 9.4` | yes |
| `numnah_bagreef` | `od (GNU coreutils) 9.4` | yes |
| `arbour_surfie` | `./arbour_surfie (GNU sed) 4.9` | yes — via the parenthetical |
| `boildown_chiam` | `boildown_chiam 1.12` | **no** |

5/6 in 6 invocations.

### Three channels, measured per tool

| Renamed | Real | Error output names the real tool | `<tool>_*` symbols in `strings` | `--version` names it |
|---|---|---|---|---|
| `resack_unluck` | curl | **yes** | **103** | yes |
| `dulias_tritons` | tar | no | 28 | yes |
| `boildown_chiam` | gzip | no | 1 | no |
| `arbour_surfie` | sed | no | 1 | yes |
| `latish_grip` | sort | no | 0 | yes |
| `numnah_bagreef` | od | no | 0 | yes |

- **Error output.**  Most GNU tools derive their diagnostic prefix
  from `argv[0]`, so they obligingly print the *scrambled* name —
  denial works there.  `curl` does not: it carries its own name as
  a literal and prints `curl: option --zzz is unknown` regardless
  of how it was invoked.
- **Dynamic symbols.**  `curl` links `libcurl` and exposes 103
  `curl_*` symbols.  These are needed for dynamic linking;
  stripping does not remove them.  Only static linking plus a
  strip would, which is not available for a distro binary.
- **`--version`.**  The broadest channel.  `gzip` is the only tool
  that resisted, and only because it builds every message from
  `argv[0]`.

### Why `gzip` is the interesting row

It is the existence proof that the property is **per-tool and
accidental**, not systemic.  A tool that derives all
self-reference from `argv[0]` is already denied by a rename.  We
get that for free from some tools and not others, and we currently
have no idea which, for any real host's inventory.

## What this retires

`docs/v2/threat-model.md` §2 asset 2 claimed:

> v2 hides the inventory via the mount-NS tier boundary; the
> untrusted tier sees only scrambled compounds.

The second clause is true and the conclusion does not follow.  The
compounds are scrambled; the tools announce themselves anyway.
Mount-NS hides the canonical *path* (STRIDE row I1, which stands);
it does nothing about a binary that names itself in its own
output.  Corrected in the same commit as this file, and a new
STRIDE row I9 covers the channel.

## Relation to F7

`TODO.md` F7 anticipates an adversary that must **infer** function
from behaviour — "speaks TLS on 443, therefore curl-equivalent."
Reality is cheaper than that threat model.  Nothing is inferred;
the tools volunteer.  No reasoning step, no probe strategy, no
model capability required — a shell loop suffices.

That cuts both ways.  The channel is worse than F7 assumed, and
the fix is correspondingly more mechanical.

## The fix — two options, and the second is better

Operator's framing (2026-10-14): *if everything announces itself,
we need to be lower than the announcement, or fully encapsulating
it.*  That is the correct fork, and the two branches are not
equally good.

### Option A — encapsulate (per-tool wrapper)

The scrambled name resolves to a wrapper that owns each
self-descriptive channel: intercept `--version` / `--help` / `-V` /
`-h` / `--usage` / `--manual` and answer from the per-epoch
deception table; filter stderr for tools that hardcode their own
name; deny untrusted-tier read access to the real binary so
dynamic symbols stay out of reach; rotate the deception table with
the mapping HKDF tree so a cached description from epoch N-1 is a
tripwire.

**Why this is the weaker branch.**  It is an enumeration problem.
Every tool has its own channels, the set is per-tool and
accidental (see the `gzip` row), and coverage can never be proven
— the adversary needs one leak, we need all of them.  Worse,
partial coverage is **net negative** under the operator's own
consistency caveat: a wrapper that lies on `--version` while the
real binary sits readable one directory over hands the adversary a
labelled training pair.  Option A only becomes safe once it is
exhaustive, and exhaustiveness is exactly what cannot be
established for a real inventory.

### Option B — go lower than the announcement (preferred)

Do not enumerate channels; interpose on the channel they all
share.  Every self-announcement, whatever its source, must
eventually become **bytes crossing an I/O boundary**: written to a
descriptor, or read out of the binary's own file.  Interpose
there and apply the existing per-host mapping to *data in flight*,
not just to filenames.

Two interposition points cover the measured channels:

1. **Output stream** — `v2-babbleon-launch-untrusted` already
   constructs the untrusted child's environment.  Give the child
   pipes and relay, rewriting canonical→compound in the stream.
   `curl: option --zzz is unknown` becomes
   `resack_unluck: option --zzz is unknown` for free.  This covers
   `--version`, `--help`, banners, and hardcoded stderr prefixes
   **uniformly, with no per-tool knowledge**, and it fixes the
   `curl` hardcoded-name case that Option A has to special-case.
2. **File read path** — serve the binary's bytes through a
   filtering view (FUSE, or an overlay in the existing mount-NS
   tier) so that `strings` and the dynamic symbol table read
   compounds rather than `curl_*`.  This is the static channel,
   and it is the one that cannot be fixed by stripping.

**Why this is strictly better.**  One mechanism, uniform coverage,
no enumeration, and no claim of exhaustiveness required — a tool
Babbleon has never seen is covered on first run.  It also reuses
machinery that already exists (the launcher, the mount-NS tier,
the mapping) rather than adding a per-tool artifact.

**Why it is tractable here specifically.**  Stream rewriting is
usually fragile because an adversarial emitter can evade a
data-flow filter by splitting or encoding its output.  That is not
this threat model: the *tools* are not adversarial.  `curl` is not
trying to leak its identity; it just does.  The adversary is a
separate process reading the tool's output, and it cannot make
`curl` encode its own banner.  A streaming matcher with a carry
buffer across write boundaries is therefore sufficient, and the
usual objection to output filtering does not apply.

### Known limits of Option B, stated up front

- **Legitimate canonical-name consumers break.**  Build scripts
  that parse `curl --version` for a compatibility check will read
  a compound.  Under full enclosure (F2) that is acceptable by
  construction — everything inside went through admission — but it
  is a real coupling between this mechanism and the enclosure
  model, not an independent fix.
- **Library identity still leaks** via the dynamic linker's own
  resolution and `/proc/self/maps`.  Already filed as limitation
  I6; Option B narrows it rather than closing it.
- **True behavioural inference is untouched, and it is the
  ceiling.**  An adversary that observes a binary open a socket
  to :443 and complete a TLS handshake has identified a
  curl-equivalent without reading one name, and no amount of name
  rewriting prevents that — rewriting the *behaviour* would break
  the tool.  That is the original F7 question, and it survives
  both options.  Everything here only closes the cheap channel;
  it buys the right to start worrying about the expensive one.

## Option B measured — the name channel closes, two others open

Prototype: `streamfilter.py` in the pilot scratch dir — a streaming
canonical→compound rewriter with a carry buffer across write
boundaries, wrapping the child's stdout+stderr.

**Result 1 — the name channel closes completely.**  0/6 tools
self-identify by name through the filter.  The `curl`
hardcoded-stderr case (`curl: option --zzz is unknown`, which
ignores `argv[0]` and which Option A would have to special-case)
is fixed with **no per-tool knowledge**:

```
resack_unluck: option --zzz-not-a-flag: is unknown
resack_unluck: try 'resack_unluck --help' or ... for more information
```

That is the predicted benefit, and it holds.

**Result 2 — a version-number channel opens.**  The filtered
output still carries `4.9`, `1.12`, `1.35`, `9.4`, `9.4`,
`8.5.0 ... /3.0.1`.  Handed *only* that filtered text and asked to
identify the tools, an evaluator recovered **4 of 6 at high
confidence** and a 5th (gzip) at medium:

| Filtered row | Recovered | Confidence | On what |
|---|---|---|---|
| `(ORGNAME <self>) 4.9` | sed | high | shape = package==program; 4.9 fits sed, not grep/gawk |
| `(ORGNAME <self>) 1.35` | tar | high | same shape; 1.35 is a tar release |
| `8.5.0 (x86_64-pc-linux-gnu) libX/8.5.0 tlsprovider/3.0.1` | curl | high | `lib<name>/<same ver>` self-pairing + TLS field is curl's alone |
| `<name> 1.12` | gzip | medium | bare `name ver` form, no parenthetical |
| `(tritonware) 9.4` ×2 | coreutils | high (package) / **low (which binary)** | package≠program is the coreutils signature |

**Result 3 — output shape is a classifier, independent of names.**
This is the load-bearing finding.  `prog (PACKAGE) ver` with
package == program identifies the sed/tar/gawk family;
package ≠ program identifies coreutils; bare `name version`
identifies gzip; `name ver (triple) libname/ver TLS/ver`
identifies curl.  Every name was replaced and the *format* still
discriminated.

This is `V2_PLAN.md`'s opening critique of v1 — "the scramble
defeats *lexical* recognition; it does not defeat *structural*
recognition" — recurring on a new surface.  v1 lost to shape in
source; a name-only output filter loses to shape in output.  The
fix is the same in kind as L3/L4 were for source: the relay must
**synthesize uniform output** for every tool — identical shape,
identical field set, per-epoch values — rather than rewriting
names inside each tool's native format.  That denies the version
values and the shape together.

**Result 4 — filter effectiveness is inversely proportional to
output verbosity.**  The two coreutils binaries came out genuinely
protected: their `--version` carries no per-program information, so
scrambling the package name sufficed.  `curl` is the worst case
because it volunteers the most.  Practical consequence: triage a
real inventory by how much each tool says about itself, rather
than treating all tools alike.

**Result 5 — the version *set* leaks the host.**  sed 4.9 + tar
1.35 + coreutils 9.4 + curl 8.5.0 + gzip 1.12 pins the host to the
Ubuntu 24.04 LTS / Debian-13 era.  That identifies the whole
expected tool inventory and its CVE surface — plausibly worth more
than identifying any single binary — and **it is not in the asset
model** (`threat-model.md` §2).  Filed as an asset gap.

## Read channel — a constraint that forecloses byte rewriting

Measured on the same binary: 60 unique `curl_*` names, 89
occurrences, first at byte offset 5165 — i.e. `.dynstr`, the
dynamic string table.  These are **imported** symbols: the loader
resolves them against `libcurl.so` by name at load time, and
`.dynsym` references them by offset into `.dynstr`.

So they are length-sensitive twice over.  Rewriting one shifts
every later offset, and the rewritten name must still match
libcurl's exported name.  Length-preserving substitution is
possible in principle — the wordlist carries 7 186 exact-4 words,
45 872 exact-10, 14 149 exact-14, thinning to 1 471 at 18 and 74
at 22, and the `curl_*` symbols span 8-24 chars so compounds
rather than single words would be required — but it cannot satisfy
the second condition without also rewriting libcurl's exports,
which every other consumer shares.

**The constraint that follows, which was not previously stated
anywhere:**

> The untrusted tier cannot be allowed to *execute* a binary while
> being denied the ability to *read* that binary's symbol names.
> Execution requires a loader running in that tier's context to
> read `.dynstr`.  Filtered bytes mean the binary will not load;
> real bytes mean `strings` works.  No single-file view satisfies
> both.

Therefore the untrusted tier must get **neither read nor exec** on
the real binary: a trusted-tier helper execs it and relays I/O.
Option A's "encapsulate" and Option B's "go lower" converge on
the same architecture once the loader is followed through —
encapsulation at the *process* boundary, interposition on the
stream.  That is the design, and it subsumes both branches above.

## Limitations

1. **N is small.**  Six tools, one host, one distro.  The
   direction is unambiguous; the 5/6 ratio is not a population
   estimate.  A real inventory (`ssh`, `aws`, `gh`, `python3`,
   `git`, ...) must be swept before any claim about coverage.
2. **Source is out of scope here.**  This says nothing about
   whether L2-L12 deny recovery from preprocessed source.  That
   remains the F6 question and is still unmeasured.
3. **One task only.**  "Which tool fetches a URL."  Inventory
   reconstruction is the easiest possible recon goal; harder goals
   may not fall as cheaply.

## Provenance, including a discarded rig

The first attempt at this measurement was **invalid and its
results are discarded**.  It wrapped each tool in a compiled shim
that embedded `/usr/bin/<tool>` as a plaintext string, so `strings`
on the *instrument* revealed the answer.  Six agent trials all
reported `channel: "static-strings"` while reading the harness,
not the tools.  Two of them diagnosed the flaw unprompted.

Same failure class as this crate's own `CORRECTIONS.md`: a
benchmark measuring an artifact of its own construction.  Recorded
here because the lesson is the reusable part — **the instrument
must not contain the answer**, and an agent trial that succeeds
suspiciously fast is evidence about the rig before it is evidence
about the defence.

The measurement above uses no wrapper at all: real binaries,
renamed, inspected directly.  It needed no agent, which is itself
the finding.

Pre-registration (design and decision rule, written before any
trial): `PRE-REGISTRATION.md` in the pilot scratch directory,
reproduced in the commit message of this file.

## Decision this forces

The pre-registered rule was: *denial-alone identifies in <=5
probes at >80% success → semantic denial is a speed bump; stop and
redesign before building F2/F3/F4.*

Measured: 6 probes, 83%.  On the binary surface that is the
redesign condition.  The binary tier needs the mediating wrapper
before the enclosure model (F2) or the rotation architecture (F4)
are worth their cost, because both assume an untrusted tier that
cannot enumerate the host's tools — and today it can, in six
commands.
