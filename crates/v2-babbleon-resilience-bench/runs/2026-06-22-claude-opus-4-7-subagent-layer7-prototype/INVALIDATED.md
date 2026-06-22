# This run is invalidated

See `../../CORRECTIONS.md` for the technical reason and
`../../BENCHMARK-DESIGN.md` for the requirements a replacement
run must satisfy.

Summary: every numerical result in `runs.jsonl` measures the
absence of literal-scrambling rather than scramble strength.
The challenge corpus embedded the recovery target as a string
literal (or as `chr()` ordinals); L2+L3 do not transform
literals; therefore the literals survived; therefore the
adversary recovered them.  The 100% crack rate is a tautology,
not a finding.

The artifacts in this directory (prompts, answers, runs.jsonl,
README.md) remain on disk as historical record.  Do NOT cite
the numbers in this directory as evidence of scramble strength
in any document, commit message, HANDOFF block, or external
communication.
