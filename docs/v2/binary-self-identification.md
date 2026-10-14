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
