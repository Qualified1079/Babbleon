import unittest

from babbleon.dialect import AgentSurface, Dialect, ToolSpec
from babbleon.wormlab import (
    FuzzyOverlapAgent,
    NaiveTriggerAgent,
    craft_informed_payload,
    craft_payload,
)


def make_surface() -> AgentSurface:
    return AgentSurface(
        system_prompt=(
            "When asked to forward a message, use the FORWARD_TO marker "
            "and call send_email."
        ),
        tools=(
            ToolSpec("send_email", "Send an email message.", ("to_address", "body")),
        ),
        markers={"forward": "FORWARD_TO"},
    )


class TestWormLab(unittest.TestCase):
    def test_payload_propagates_against_monoculture_default(self):
        canonical_surface = make_surface()
        payload = craft_payload("send_email", "FORWARD_TO")

        # A second, undiversified install --- the monoculture case: same
        # framework, same tool names, no Babbleon in front of it.
        install_a = NaiveTriggerAgent("install-a-undiversified", canonical_surface)
        event = install_a.ingest(payload)

        self.assertTrue(event.propagated)
        self.assertEqual(event.tool_triggered, "send_email")

    def test_payload_fails_against_diversified_install(self):
        canonical_surface = make_surface()
        payload = craft_payload("send_email", "FORWARD_TO")

        dialect = Dialect.generate("install-b-2026", canonical_surface)
        install_b = NaiveTriggerAgent("install-b-diversified", dialect.surface)
        event = install_b.ingest(payload)

        self.assertFalse(event.propagated)
        self.assertIsNone(event.tool_triggered)

    def test_payload_crafted_against_one_dialect_fails_against_another(self):
        canonical_surface = make_surface()
        dialect_a = Dialect.generate("install-a", canonical_surface)
        dialect_b = Dialect.generate("install-b", canonical_surface)

        diversified_tool_a = dialect_a.surface.tools[0]
        diversified_marker_a = dialect_a.surface.markers["forward"]
        payload = craft_payload(diversified_tool_a.name, diversified_marker_a)

        # Same payload, now targeted at a differently-seeded install ---
        # this is the actual anti-monoculture claim: a worm tuned against
        # one install's dialect doesn't transfer to the next one for free.
        install_b = NaiveTriggerAgent("install-b", dialect_b.surface)
        event = install_b.ingest(payload)

        self.assertFalse(event.propagated)


class TestFuzzyOverlapAgent(unittest.TestCase):
    """Tests the honest limitation flagged in claude.md and handoff.md:
    does synonym-pool word substitution alone survive an attacker who
    knows the pool (Kerckhoffs's principle) but not the per-install seed?
    """

    def test_naive_literal_payload_does_not_fool_fuzzy_agent_across_dialects(self):
        # A payload built for one dialect's exact vocabulary still
        # shouldn't transfer to a different seed under fuzzy matching
        # either -- it wasn't built to be vocabulary-general.
        canonical_surface = make_surface()
        dialect_a = Dialect.generate("install-a", canonical_surface)
        dialect_b = Dialect.generate("install-b", canonical_surface)
        payload = craft_payload(
            dialect_a.surface.tools[0].name, dialect_a.surface.markers["forward"]
        )

        install_b = FuzzyOverlapAgent("install-b", dialect_b.surface)
        event = install_b.ingest(payload)
        self.assertFalse(event.propagated)

    def test_informed_payload_still_propagates_against_fuzzy_matching(self):
        # The Kerckhoffs's-principle-aware attacker: doesn't know the
        # seed, but knows the algorithm and its public synonym pool, and
        # sprays the whole pool. This SHOULD still trigger a fuzzy
        # description-overlap matcher on any seed, because whichever
        # synonym the dialect landed on is present in the sprayed text.
        # This is the concrete evidence behind claude.md's claim that the
        # salted name (not the synonym substitution) is what's actually
        # load-bearing.
        canonical_surface = make_surface()
        payload = craft_informed_payload()

        for seed in ("install-a", "install-b", "install-c"):
            dialect = Dialect.generate(seed, canonical_surface)
            install = FuzzyOverlapAgent(seed, dialect.surface)
            event = install.ingest(payload)
            self.assertTrue(event.propagated, f"expected propagation against seed {seed}")

    def test_informed_payload_still_fails_against_naive_literal_matching(self):
        # The same informed payload does NOT know the salted tool name,
        # so it still fails against the literal-string floor case --
        # the salt, not the vocabulary, is doing the work there.
        canonical_surface = make_surface()
        payload = craft_informed_payload()

        dialect = Dialect.generate("install-a", canonical_surface)
        install = NaiveTriggerAgent("install-a", dialect.surface)
        event = install.ingest(payload)
        self.assertFalse(event.propagated)


if __name__ == "__main__":
    unittest.main()
