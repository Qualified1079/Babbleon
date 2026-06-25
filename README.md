# Babbleon

[![ci](https://github.com/qualified1079/babbleon/actions/workflows/ci.yml/badge.svg)](https://github.com/qualified1079/babbleon/actions/workflows/ci.yml)
[![scorecard](https://github.com/qualified1079/babbleon/actions/workflows/scorecard.yml/badge.svg)](https://github.com/qualified1079/babbleon/actions/workflows/scorecard.yml)
[![codeql](https://github.com/qualified1079/babbleon/actions/workflows/codeql.yml/badge.svg)](https://github.com/qualified1079/babbleon/actions/workflows/codeql.yml)

Per-host randomized namespace obfuscation that breaks LLM-driven
automated attackers. The same machine presents two filesystem views:
a **trusted** view (humans, real names) and an **untrusted** view
(payloads, scrambled compound names). The mapping is the only secret;
the algorithm and code are public (Kerckhoffs).

An attacker landing in an untrusted process sees `curl` as something
like `riverstoneanvilfreckle` — but only on *this* host. Their cached
exploits, hardcoded paths, and `which curl` reconnaissance all
misfire. Rotate the mapping and yesterday's leaked recipes are dead.

This is a defense designed for the era where the cheap, scalable
attacker is an LLM running a generic playbook.

## Status

v2 is in active development under `crates/v2-*`. The v2
preprocessor pipeline currently composes six scramble layers:

- **L2 — dynamic identifier scramble** (`crates/v2-babbleon-preprocessor/
  src/identifier_scrambler.rs`). Language-agnostic. Every
  whitespace-delimited token in the source — keywords, operators,
  identifiers, string literals, punctuation — is collected and
  assigned per-epoch HKDF-derived compound aliases. `ALIAS_COUNT=3`
  multi-alias per token: each token gets 3 independent compounds
  cycling across occurrences to defeat frequency analysis.
- **L3 — whitespace-as-words** (`scrambler.rs` + `unscrambler.rs`).
  Every newline, space, tab, indent-open, and indent-close is
  replaced with a per-epoch compound. The scrambled file is one
  continuous wall of words — no visible structure.
- **L4 — chunk reorder with position markers** (`chunk_reorder.rs`).
  Top-level statements are reordered deterministically per epoch.
  Each chunk carries a `__bbnpos<N>__` marker the unscrambler reads
  to restore original order. Defeats "imports first, helpers next,
  main last" structural fingerprinting.
- **L5 — decoy injection** (`decoy_injection.rs`). Per-epoch decoy
  `__bbndecoy<N>__` tokens are injected at depth-0 positions
  (~25% of the original token count). Raises attacker cost to
  locate the live code within the rotation window. The unscrambler
  recognizes and strips them by prefix.
- **L6 — direction segment reversal** (`direction_reversal.rs`).
  The L3 body is split into variable-length char chunks
  (`[16, 48]` chars) and ~50% are reversed per a per-epoch
  xorshift PRNG. Wordlist substring matches against the original
  compound names fail; visual reading order is destroyed. Reversal
  is involutive so the unscrambler re-applies the same per-epoch
  pattern to undo it.
- **L12 — tokenizer-hostile noise** (`tokenizer_noise.rs`). The L3
  body bytes are perturbed with zero-width characters (ZWSP/ZWNJ/
  ZWJ at U+200B/U+200C/U+200D) injected at deterministic per-epoch
  positions, and Latin-to-Cyrillic homoglyph substitutions on
  `a c e i o p x y` (U+0430/0441/0435/0456/043E/0440/0445/0443). An
  attacker piping the raw bytes into an LLM tokenizer gets a
  multi-x token-count inflation and broken BPE merges; the trusted
  unscrambler strips the noise content-based before L3⁻¹.

Scrambled-file format: a 4-line header (magic, epoch, sorted token
list, separator) followed by the L3 body. The token list is embedded
so the unscrambler can re-derive the L2 mapping from the daemon
without needing the original source. Security comes from the
compounds being derived from the per-host secret, not from hiding
which tokens exist.

Pipeline order:
- **Scramble**: tokenize → L4 → L5 → L2 → L3 → **L6** → **L12** → encode header
- **Unscramble**: decode header → **L12⁻¹** → **L6⁻¹** → L3⁻¹ → L2⁻¹ → L5⁻¹ → L4⁻¹ → emit

See **TODO.md** for the ship checklist (open and deferred items with
rationale inline), **PLAN.md** / **V2_PLAN.md** for architecture,
**RUST_PLAN.md** for the Rust realization, and **RESEARCH.md** for the
threat-model and prior-art notes.

## Try it

    cargo run -p babbleon-cli -- demo

Runs a no-syscall sandbox demo: builds a vault, shows both views,
runs an attacker simulation against the scrambled view, rotates,
re-runs, and triggers a honey tripwire.

For the adversarial naming-layer harness against a frontier LLM, open
`tools/scrambler/index.html` in a browser. No server, no deps.

## Layout

    crates/babbleon/           library — mapping, vault, enforcement
    crates/babbleon-cli/       `babbleon` binary
    crates/babbleon-ns-helper/ setuid helper (M3)
    crates/babbleon-pam/       PAM module (M3)
    tools/scrambler/           browser-based LLM test harness
    tools/rotation-benchmark/  rotation cost measurement
    tools/tokenizer-benchmark/ BPE token cost measurement
    fuzz/                      cargo-fuzz harnesses (3 targets)
    policies/                  AppArmor + SELinux confinement templates
    docs/                      threat model, CWE audit, SSDF policy, ...

## Security

- Vulnerability disclosure: see [`SECURITY.md`](SECURITY.md)
- Release verification: see [`docs/verify-release.md`](docs/verify-release.md)
  — cosign keyless signatures + SLSA L3 provenance + signed SBOM
- Threat model: [`docs/threat-model.md`](docs/threat-model.md) (AI-attacker
  classification) and [`docs/threat-model-stride.md`](docs/threat-model-stride.md)
  (STRIDE-formatted)
- CWE Top 25 audit: [`docs/cwe-top25-audit.md`](docs/cwe-top25-audit.md)
- SSDF mapping: [`docs/secure-development-policy.md`](docs/secure-development-policy.md)

## License

PolyForm Noncommercial 1.0.0. Commercial use, support, and the
enterprise extension surface (escrow, SIEM sinks, console) ship out
of a separate private repository.
