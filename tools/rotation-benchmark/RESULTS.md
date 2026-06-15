# Rotation-rate benchmark — results

Measured cost of the userspace portion of a Babbleon rotation,
parameterized by tracked-tool count and by whether the wordlist
permutation has been pre-built in background.

## Run conditions

- Wordlist: `crates/babbleon/wordlist/words.txt` (369 652 words).
- Iterations per config: 30 (after global warmup).
- Wrappers regenerated each iteration (default).
- Vault re-seal **excluded** (that path is Argon2id-bound at ~250 ms
  and is the *cold* rotation, not what the connected-attacker
  defense cares about).
- Kernel-side bind-mount swap **excluded** (root-only; see RESEARCH T9
  for the ~50 ms / 200 mounts estimate).

## Numbers (median per rotation)

| N tracked | path | mapping rebuild | wrapper regen | total | max rate |
|-----------|------|-----------------|---------------|-------|----------|
| 10        | cold | 18.0 ms         | 0.5 ms        | 18.7 ms | 53 Hz |
| 10        | warm | 0.19 ms         | 0.4 ms        | 0.73 ms | 1360 Hz |
| 100       | cold | 18.3 ms         | 22.9 ms       | 42.4 ms | 24 Hz |
| 100       | warm | 0.48 ms         | 22.6 ms       | 24.2 ms | 41 Hz |
| 1 000     | cold | 29.3 ms         | 404 ms        | 442 ms  | 2.3 Hz |
| 1 000     | warm | 2.75 ms         | 363 ms        | 375 ms  | 2.7 Hz |

**cold** = the wordlist permutation has not been built yet for this
(host_secret, epoch) pair; the rotation pays for the Fisher-Yates over
the full 370k-word vocabulary (~18 ms).

**warm** = the permutation has been pre-built in background and is
cached; the rotation only pays for compound generation + wrapper
render.

## Interpretation

1. **Sub-second rotation is achievable today** for any tracked-tool
   count we plausibly ship (default `DEFAULT_TRACKED` is ~14 tools, so
   we are firmly in the N=10–100 regime).  Warm-path rotation at N=14
   should sit comfortably below 1 ms; at N=100 around 24 ms.

2. **The wordlist permutation is the dominant fixed cost.**  An ~18 ms
   Fisher-Yates over 370k entries every time a fresh epoch is reached.
   Pre-computing the next epoch's permutation in a background thread
   reduces the rotation-tick cost by ~100×.  This is the most
   impactful single architectural change for high-frequency rotation.

3. **Wrapper file IO dominates above N≈100.**  Each wrapper script is
   ~0.2–0.4 ms to render and write.  For the default tracked set this
   is invisible; at N=1000+ it becomes the binding constraint.  A
   future optimisation: emit a single wrapper binary that consults a
   runtime mapping table, so rotation = atomic table file swap (one
   write instead of N).

4. **Per-minute or per-second rotation is comfortably within budget.**
   Sub-second (e.g. one rotation per 250 ms) is also achievable with
   the warm-path numbers above.  Millisecond-class rotation needs the
   wrapper-regen redesign called out above.

## Implications for the connected-attacker defense

Threat B (docs/threat-model.md) — covering E3 hybrid and E4 swarm —
is closed when the rotation period drops below the relay
round-trip the attacker uses to refresh its per-host vocabulary.
Typical RTTs:

- E3 LLM-API exfil + response: 1–5 s on a good link.
- E4 peer-to-peer swarm propagation: dominated by hop count and
  link latency; sub-second is plausible on a fast LAN/Tor circuit,
  multi-second is typical on the open internet.

Against those numbers:

- A 250 ms rotation period defeats E3 with a healthy margin even on a
  slow link, and beats most realistic E4 propagation windows.
- We can sustain 250 ms rotations at N≤100 today on this hardware
  without further engineering (warm path, ~24 ms per rotation,
  ~10 % duty cycle).
- 25 ms rotations (40 Hz) are achievable for N≤10 today; this would
  defeat sub-100 ms swarm propagation in the unlikely case anyone
  builds one.

These conclusions are **for this hardware, this wordlist, this
implementation.**  No PLAN- or README-level claim about supported
rotation rate should be made without re-running the benchmark on the
target deployment hardware.

## Future work

- **Background permutation pre-build.**  Architectural change in
  `mapping/`: spawn a thread on epoch advance that builds epoch+1's
  permutation table.  Validates the warm-path numbers as the actual
  hot-path numbers in production.
- **Unified runtime wrapper.**  One binary, runtime table lookup;
  rotation = one file write.  Bench should show millisecond-class
  rotation at any N.
- **Cross-namespace bind-mount swap cost** measurement.  Needs root and
  a real PID namespace; deferred to the bare-metal hardware that
  arrives later.
- **End-to-end:** wire vault re-seal in (Argon2id ~250 ms) and measure
  the *cold* rotation path's true cost.  The cold path is the floor on
  recovery / restart rotation, not steady-state rotation.
