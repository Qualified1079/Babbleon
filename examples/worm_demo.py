#!/usr/bin/env python3
"""Runnable demonstration of the babbleon/wormlab.py effect.

Run from the repo root: python3 examples/worm_demo.py

Three scenarios, in increasing order of attacker sophistication --- see
babbleon/wormlab.py's module docstring and claude.md's "honest
limitation" section for what each one does and doesn't prove:

1. A Morris-II-shaped payload built for one install propagates cleanly
   to an identically-configured (undiversified / monoculture) install.
2. The same payload fails against a differently-seeded, diversified
   install --- NaiveTriggerAgent can't find its literal tool name/marker.
3. An attacker who knows Babbleon's algorithm and public synonym pool
   (Kerckhoffs's principle) but not the per-install seed can still
   defeat a fuzzy, description-overlap matcher by spraying the whole
   pool --- but still can't guess the per-install-salted literal name.
4. A worm that has somehow already obtained this install's exact renamed
   tool/param identifiers (full naming-layer win) still can't invoke the
   tool if it assumes the wrong calling *shape* --- a second, independent
   diversification axis from renaming.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from babbleon.dialect import AgentSurface, Dialect, ToolSpec
from babbleon.runtime import DialectRuntime
from babbleon.wormlab import (
    FuzzyOverlapAgent,
    NaiveTriggerAgent,
    ShapeAssumingWorm,
    craft_informed_payload,
    craft_payload,
)


def make_surface() -> AgentSurface:
    return AgentSurface(
        system_prompt=(
            "You are an email assistant. When asked to forward a message, "
            "use the FORWARD_TO marker and call send_email."
        ),
        tools=(
            ToolSpec("send_email", "Send an email message.", ("to_address", "body")),
        ),
        markers={"forward": "FORWARD_TO"},
    )


def report(label: str, event) -> None:
    outcome = "PROPAGATED" if event.propagated else "blocked"
    print(f"  [{outcome:>10}] {label} (install={event.install!r})")


def main() -> None:
    surface = make_surface()
    payload = craft_payload("send_email", "FORWARD_TO")

    print("Scenario 1: monoculture default (no Babbleon)")
    install_a = NaiveTriggerAgent("install-a-undiversified", surface)
    report("naive payload vs. undiversified install", install_a.ingest(payload))

    print("\nScenario 2: same payload vs. a diversified install")
    dialect_b = Dialect.generate("install-b-2026", surface)
    print(f"  install-b's dialect: tool renamed to {dialect_b.surface.tools[0].name!r}, "
          f"marker renamed to {dialect_b.surface.markers['forward']!r}")
    install_b = NaiveTriggerAgent("install-b-diversified", dialect_b.surface)
    report("same naive payload vs. diversified install", install_b.ingest(payload))

    print("\nScenario 3: Kerckhoffs-aware attacker vs. a fuzzy-matching agent")
    informed_payload = craft_informed_payload()
    for seed in ("install-c", "install-d", "install-e"):
        dialect = Dialect.generate(seed, surface)
        naive = NaiveTriggerAgent(seed, dialect.surface)
        fuzzy = FuzzyOverlapAgent(seed, dialect.surface)
        report(f"informed payload vs. literal-match agent ({seed})", naive.ingest(informed_payload))
        report(f"informed payload vs. fuzzy-match agent   ({seed})", fuzzy.ingest(informed_payload))

    print("\nScenario 4: worm already has your exact renamed identifiers -- now what?")
    for seed in ("install-a", "install-b"):
        dialect = Dialect.generate(seed, surface)
        impl_calls = []
        runtime = DialectRuntime(
            dialect,
            {"send_email": lambda to_address, body: impl_calls.append((to_address, body))},
        )
        tool = dialect.surface.tools[0]
        worm = ShapeAssumingWorm(
            tool.name, {tool.params[0]: "victim@example.com", tool.params[1]: "spam"}
        )
        succeeded = worm.attempt(runtime)
        outcome = "INVOKED" if succeeded else "rejected (wrong shape)"
        print(f"  [{outcome:>22}] full naming win vs. {dialect.calling_convention}-convention install ({seed})")

    print(
        "\nConclusion: renaming alone (a small public synonym pool) doesn't "
        "survive an attacker who knows the pool; the per-install random salt "
        "is what actually carries the security margin. Calling-convention "
        "diversification is a second, independent axis that holds even when "
        "naming is fully compromised. See claude.md."
    )


if __name__ == "__main__":
    main()
