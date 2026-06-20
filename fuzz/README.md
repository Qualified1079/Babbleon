# Fuzz harnesses

Three `cargo-fuzz` targets covering the parsing + rendering surfaces
that the CWE-Top-25 audit flagged.  Each one is a thin wrapper around
the public API of the `babbleon` crate so the fuzzer drives realistic
end-to-end paths.

| Target | Surface | Rationale |
|---|---|---|
| `honey_fifo_line` | `HoneyFifoReader::run` JSON parser | CWE-400 length bound is enforced at the reader; the parser still needs survival under malformed JSON, oversized strings, surrogate pairs, integer-overflow values. |
| `fpe_roundtrip` | `mapping::fpe::{encrypt, decrypt}` | Asserts `decrypt(encrypt(x)) == x` — the FPE soundness property as a fuzz target. |
| `wrapper_render` | `enforcement::wrapper::write_wrapper` | Drives the renderer with arbitrary decoy-banner inputs; checks the output is well-formed UTF-8 and that the printf-line's single-quote escape balances. |

## Running

```sh
# One-time setup.
rustup install nightly
cargo install cargo-fuzz

# 60 s smoke run per target.
cargo fuzz run honey_fifo_line -- -max_total_time=60
cargo fuzz run fpe_roundtrip   -- -max_total_time=60
cargo fuzz run wrapper_render  -- -max_total_time=60
```

## CI integration

Not on the per-PR CI loop — libfuzzer needs nightly and a long-running
job. Filed in `TODO.md` under "fuzz smoke runs on a weekly schedule"
for a future workflow that runs each target for ~5 min weekly.

Crashes go into `fuzz/artifacts/<target>/`; corpora at
`fuzz/corpus/<target>/`.

## What these are NOT

These harnesses are not a substitute for `cargo audit`, `cargo deny`,
or the property-based tests in `crates/babbleon/tests/`.  They cover
the *byte-level surface* of public parsers — places where a malformed
input could plausibly do harm.

Filed but not yet implemented:
  - **Audit-log signed-verify fuzzer** — feed arbitrary JSON lines
    plus arbitrary candidate signatures to `verify_signed` and confirm
    no panic.
  - **Vault unseal fuzzer** — feed arbitrary bytes as a vault to
    `Vault::unseal` and confirm bounded error response.
