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

Early development. M1 (Rust sandbox demo) lands; M3 (real Linux
namespace enforcement with PAM + setuid helper) is the load-bearing
piece and is next.

See **TODO.md** for the ship checklist (open and deferred items with
rationale inline), **PLAN.md** for architecture, **RUST_PLAN.md** for
the Rust realization, and **RESEARCH.md** for the threat-model and
prior-art notes.

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
