import unittest

from babbleon.dialect import AgentSurface, Dialect, ToolSpec
from babbleon.wormlab import NaiveTriggerAgent, craft_payload


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


if __name__ == "__main__":
    unittest.main()
