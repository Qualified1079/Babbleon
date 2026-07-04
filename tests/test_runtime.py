import unittest

from babbleon.dialect import AgentSurface, Dialect, ToolSpec
from babbleon.runtime import DialectRuntime, UnknownToolError


def make_surface() -> AgentSurface:
    return AgentSurface(
        system_prompt="Send email via send_email.",
        tools=(ToolSpec("send_email", "Send an email.", ("to_address", "body")),),
        markers={},
    )


class TestDialectRuntime(unittest.TestCase):
    def setUp(self):
        self.calls = []
        surface = make_surface()
        self.dialect = Dialect.generate("install-a", surface)
        self.runtime = DialectRuntime(
            self.dialect,
            {"send_email": lambda to_address, body: self.calls.append((to_address, body))},
        )

    def test_dispatch_translates_diversified_call_to_canonical_impl(self):
        diversified_tool = self.dialect.surface.tools[0]
        diversified_kwargs = {
            diversified_tool.params[0]: "alice@example.com",
            diversified_tool.params[1]: "hello",
        }
        self.runtime.dispatch(diversified_tool.name, diversified_kwargs)
        self.assertEqual(self.calls, [("alice@example.com", "hello")])

    def test_dispatch_unknown_tool_raises(self):
        with self.assertRaises(UnknownToolError):
            self.runtime.dispatch("send_email", {"to_address": "x", "body": "y"})

    def test_application_logic_never_sees_diversified_names(self):
        # The implementation map is keyed by canonical names only; a
        # correct dispatch call must never leak a diversified param name
        # into the canonical implementation's kwargs.
        received_kwargs = {}

        def impl(**kwargs):
            received_kwargs.update(kwargs)

        runtime = DialectRuntime(self.dialect, {"send_email": impl})
        diversified_tool = self.dialect.surface.tools[0]
        runtime.dispatch(
            diversified_tool.name,
            {diversified_tool.params[0]: "bob@example.com", diversified_tool.params[1]: "hi"},
        )
        self.assertEqual(set(received_kwargs), {"to_address", "body"})


if __name__ == "__main__":
    unittest.main()
