# Babbleon

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

See **TODO.md** for the ship checklist, **PLAN.md** for architecture,
**RUST_PLAN.md** for the Rust realization, **RESEARCH.md** for the
threat-model and prior-art notes, and **DEFERRED.md** for items
explicitly punted with rationale.

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
    tools/scrambler/           browser-based LLM test harness

## License

PolyForm Noncommercial 1.0.0. Commercial use, support, and the
enterprise extension surface (escrow, SIEM sinks, console) ship out
of a separate private repository.
