# rotation-benchmark

Measures the userspace cost of a Babbleon rotation cycle and bounds
the maximum supportable rotation rate.

## Why this exists

`docs/threat-model.md` describes a *connected* attacker (Threat B —
expressions E3 hybrid and E4 swarm).  Either a single small on-host
agent with a live link to a large external model, or a peer-to-peer
network of small models sharing exploits at network-propagation
speed.  Neither needs to crack the scramble on-host — they relay
the current vocabulary out, receive translated instructions, and
execute within the rotation window.  The defense against both is
**rotating the mapping faster than the relay round-trip**.  That
makes the maximum rotation rate a first-class threat-model number.

This benchmark measures the components Babbleon controls in software:
the mapping rebuild, and (optionally) wrapper-script regeneration.
The kernel-side bind-mount swap is out of scope here; see RESEARCH
T9 for the existing estimate.

The result: **sub-second rotation is achievable today** for typical
tracked-tool counts.  See `RESULTS.md`.

## Build and run

Standalone crate (own `[workspace]`), depends on the local `babbleon`
crate by path so the production mapping/wrapper code is exercised
directly.

    cd tools/rotation-benchmark
    cargo run --release -- --tool-counts 10,100,1000 --iterations 30

Options:

    --tool-counts N,N,N   sweep these tracked-tool sizes (default 10,100,1000,10000)
    -i, --iterations N    samples per config (default 50)
    --no-wrappers         skip wrapper IO; mapping-only timing

## What it measures

Per configuration (N tracked tools), runs N rotations along two paths:

- **Cold path**: each iteration uses a unique `(host_secret, epoch)`
  pair so the wordlist permutation cache misses.  Measures the worst
  case (first rotation after process start, or after restart).

- **Warm path**: reuses one pre-built permutation.  Measures the
  optimised hot path, where the next epoch's permutation has been
  pre-computed in background and the rotation tick only pays for
  compound generation + wrapper render.

For each path, reports mean / median / p95 / min / max for:

- mapping rebuild (Fisher-Yates + compound name generation)
- wrapper regen (write N shell scripts)
- total rotation time

Each median is converted into a maximum rotation rate (Hz).

## Reporting policy

Same as `tools/tokenizer-benchmark/`: any rotation-rate number in
PLAN.md or threat-model.md must cite the tool count, kernel, CPU, and
benchmark configuration that produced it.
