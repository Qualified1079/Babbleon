import unittest

from babbleon.dialect import AgentSurface, Dialect, ToolSpec


def make_surface() -> AgentSurface:
    return AgentSurface(
        system_prompt=(
            "You are an email assistant. When asked to forward a message, "
            "use the FORWARD_TO marker and call send_email."
        ),
        tools=(
            ToolSpec("send_email", "Send an email message.", ("to_address", "body")),
            ToolSpec("search_web", "Search the web for a query.", ("query",)),
        ),
        markers={"forward": "FORWARD_TO"},
    )


class TestDialectDeterminism(unittest.TestCase):
    def test_same_seed_yields_identical_dialect(self):
        surface = make_surface()
        d1 = Dialect.generate("install-a", surface)
        d2 = Dialect.generate("install-a", surface)
        self.assertEqual(d1.surface, d2.surface)
        self.assertEqual(d1.tool_name_map, d2.tool_name_map)
        self.assertEqual(d1.param_name_map, d2.param_name_map)
        self.assertEqual(d1.marker_map, d2.marker_map)

    def test_different_seeds_diverge(self):
        surface = make_surface()
        d1 = Dialect.generate("install-a", surface)
        d2 = Dialect.generate("install-b", surface)
        self.assertNotEqual(d1.surface.tools, d2.surface.tools)
        self.assertNotEqual(set(d1.tool_name_map), set(d2.tool_name_map))

    def test_diversified_names_do_not_collide_with_canonical(self):
        surface = make_surface()
        dialect = Dialect.generate("install-a", surface)
        canonical_names = {t.name for t in surface.tools}
        diversified_names = {t.name for t in dialect.surface.tools}
        self.assertTrue(canonical_names.isdisjoint(diversified_names))

    def test_tool_name_map_round_trips_to_canonical(self):
        surface = make_surface()
        dialect = Dialect.generate("install-a", surface)
        canonical_names = {t.name for t in surface.tools}
        mapped_back = set(dialect.tool_name_map.values())
        self.assertEqual(canonical_names, mapped_back)

    def test_marker_token_is_diversified_and_present_in_prompt(self):
        surface = make_surface()
        dialect = Dialect.generate("install-a", surface)
        diversified_token = dialect.surface.markers["forward"]
        self.assertNotEqual(diversified_token, "FORWARD_TO")
        self.assertIn(diversified_token, dialect.surface.system_prompt)
        self.assertNotIn("FORWARD_TO", dialect.surface.system_prompt)

    def test_marker_map_resolves_back_to_logical_key(self):
        surface = make_surface()
        dialect = Dialect.generate("install-a", surface)
        diversified_token = dialect.surface.markers["forward"]
        self.assertEqual(dialect.marker_map[diversified_token], "forward")


if __name__ == "__main__":
    unittest.main()
