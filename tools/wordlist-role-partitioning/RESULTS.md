# tools/wordlist-role-partitioning — measured results (2026-07-02)

Deterministic reference tables from the four preset configurations.
Regenerate with:

```
cargo build --release
./target/release/wordlist-role-partitioning              --quiet --report-out RESULTS-baseline-default.md
./target/release/wordlist-role-partitioning --wordlist cl100k-intersect35   --quiet --report-out RESULTS-intersect-default.md
./target/release/wordlist-role-partitioning --paranoid                       --quiet --report-out RESULTS-baseline-paranoid.md
./target/release/wordlist-role-partitioning --paranoid --wordlist cl100k-intersect35 --quiet --report-out RESULTS-intersect-paranoid.md
```

Numbers are deterministic — the tool has no RNG.  Same inputs
(wordlist size + attacker knobs) always yield the same table
bit-for-bit.

## Scenario 1 — baseline wordlist + laptop-default attacker

**Wordlist**: cl100k baseline (size=369 652, mean tokens/compound=11.96)
**Attacker**: 2 000 events/epoch, 8 760 lifetime epochs, target
1e-6 lifetime collision probability, collision margin 19.93 bits.

| Role | N | Pool | Target bits | Achieved bits | p/epoch | p/lifetime |
|------|--:|-----:|------------:|--------------:|--------:|-----------:|
| `identifier`       | 4 | 13 682  | 54.96 | 54.96 | 5.71e-11 | 5.00e-7 |
| `decoy`            | 3 | 129 862 | 50.96 | 50.96 | 5.71e-11 | 5.00e-7 |
| `direction_marker` | 3 | 70 500  | 48.32 | 48.32 | 5.71e-11 | 5.00e-7 |
| `whitespace`       | 2 | 142     | 14.29 | 14.30 |    1.00  |    1.00 |
| `keyword`          | 1 | 701     |  9.45 |  9.45 |    0.58  |    1.00 |
| `prompt_injection` | 1 | 500     |  0.00 |  8.97 |    0.02  |    1.00 |

**Total pool**: 215 387 / 369 652 words (58.27% utilization).
Headroom **154 265 words**.  Verdict: **FITS**.

## Scenario 2 — intersect[3,5] wordlist + laptop-default attacker

**Wordlist**: cl100k `intersect[3, 5]` (size=223 009, mean
tokens/compound=13.80).  Same attacker as scenario 1.  Every role
row is identical to scenario 1 (the allocation is independent of
the corpus size once the pool fits) but the fit metric changes.

**Total pool**: 215 387 / 223 009 words (**96.58% utilization**).
Headroom **7 622 words**.  Verdict: **FITS**.

**Design implication.**  The `intersect[3, 5]` filter cuts a
+16 % / +14 % compound-attention-cost bump (see
`tools/wordlist-density-analysis/RESULTS.md`) at the price of
shrinking the corpus to the point where the role table is at ~97 %
utilization.  Any phase-4 addition — multi-language pool
partitioning, additional obfuscation layer, higher event count —
would push the intersect-only allocation into OVERFLOW.  The
baseline stays at 58 % utilization with the same role budget and
therefore has room for phase-4 growth.

## Scenario 3 — baseline wordlist + paranoid attacker

**Wordlist**: cl100k baseline (size=369 652).
**Attacker**: same events + lifetime, target **1e-12** lifetime
collision probability (collision margin 39.86 bits).

| Role | N | Pool | Target bits | Achieved bits | p/epoch | p/lifetime |
|------|--:|-----:|------------:|--------------:|--------:|-----------:|
| `identifier`       | 4 | 432 655    | 74.89 | 74.89 | 1.11e-16 | 9.73e-13 |
| `decoy`            | 3 | 12 986 179 | 70.89 | 70.89 | 1.11e-16 | 9.73e-13 |
| `direction_marker` | 3 | 7 049 983  | 68.25 | 68.25 | 1.11e-16 | 9.73e-13 |
| `whitespace`       | 2 | 142        | 14.29 | 14.30 |    1.00  |    1.00 |
| `keyword`          | 1 | 701        |  9.45 |  9.45 |    0.58  |    1.00 |
| `prompt_injection` | 1 | 500        |  0.00 |  8.97 |    0.02  |    1.00 |

**Total pool**: 20 470 160 / 369 652 words (**5 537.68 %
utilization**).  Verdict: **OVERFLOW**.

**Design implication.**  Under the paranoid posture, no realistic
English-only wordlist can host the provisional role table.  The
operator's options are (a) accept the laptop-default posture
(scenario 1, comfortable fit), (b) trade off a role — for example,
give the decoy role Uniqueness-mode semantics (paralleling
whitespace) and drop its pool from 13 M to ~few thousand, or (c)
grow the corpus with multi-language pools from phase 4 (HermitDave/
FrequencyWords → ~1.6 M entries at 16 languages, TODO.md phase 4).

## Scenario 4 — intersect[3,5] + paranoid

Same role rows as scenario 3 — corpus size does not change per-role
allocation until it becomes the binding constraint on OVERFLOW.

**Total pool**: 20 470 160 / 223 009 words (**9 179.07 %
utilization**).  Verdict: **OVERFLOW**.

## Sensitivity table — how the identifier pool moves with knobs

Approximate closed-form (holds when Birthday mode is active):

```
identifier_pool ≈ 2^((2·log2(events) + collision_margin + log2(lifetime)) / compound_n)
```

At `compound_n=4`, `events=2000`, `lifetime=8760`:

| Target collision p | Collision margin | Identifier pool |
|--------------------|-----------------:|----------------:|
| 1e-3               | 9.97 bits        |         2 148   |
| 1e-6 (default)     | 19.93 bits       |        13 682   |
| 1e-9               | 29.90 bits       |        87 200   |
| 1e-12 (paranoid)   | 39.86 bits       |       432 655   |

Doubling `events_per_epoch` moves the pool by `2^(2/4) = √2 ≈ 1.41×`.
Halving `secret_lifetime_epochs` shrinks the pool by `2^(-1/4) ≈
0.84×`.  Increasing `compound_n` from 4 to 5 shrinks the pool by
`~2^((-target/20)) ≈ 0.35×` at the default target.

## Recommendations

Anchored to the wordlist-density-analysis session's
recommendations (`intersect[3, 5]` or `cl100k [3, 5]`):

1. **Continue with `cl100k baseline` while phase-4 multi-language
   pools are still upstream.**  Under laptop-default the aggregate
   is at 58 % utilization — plenty of headroom for the
   role-partitioning constraint plus future phase-4 additions.
2. **Reserve `intersect[3, 5]` for after phase 4 lands.**  It
   currently sits at 97 % utilization with the six-role table.
   Adding *any* phase-4 role or splitting the identifier role into
   per-language sub-pools tips it into OVERFLOW.  Waiting until
   the corpus grows to ~1.6 M entries (HermitDave 16-language
   pool) makes the intersect filter's attention-cost gain
   consumable at zero role budget cost.
3. **Do NOT ship the paranoid preset without the phase-4 corpus.**
   Under 1e-12 the Birthday-mode roles individually demand 8-25 M
   pool words — no single-language wordlist supplies that.  The
   paranoid preset is a *stress-test posture*, useful for
   understanding the room-to-grow question; it is not a shippable
   attacker model against the 2026-07-02 corpus.
