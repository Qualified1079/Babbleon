"""Translation shim: makes the diversification in `dialect.py` invisible
to application logic.

The model only ever sees `dialect.surface` (diversified tool names,
params, markers). `DialectRuntime.dispatch` is the only place that
translates a diversified tool call back to the canonical implementation,
so the rest of the application is written against canonical names and
never has to know a dialect exists.
"""
from __future__ import annotations

from typing import Any, Callable, Dict

from babbleon.dialect import Dialect


class UnknownToolError(KeyError):
    """Raised when a tool name isn't part of this dialect's vocabulary.

    In production this is exactly the signal that a caller is using the
    wrong install's dialect (or that a worm payload from a different
    install's monoculture failed to translate) --- worth logging as a
    security-relevant event, not just a bug.
    """


class DialectRuntime:
    def __init__(self, dialect: Dialect, implementations: Dict[str, Callable[..., Any]]):
        self.dialect = dialect
        self._implementations = implementations

    @property
    def surface(self):
        return self.dialect.surface

    def dispatch(self, diversified_tool_name: str, diversified_kwargs: Dict[str, Any]) -> Any:
        canonical_tool = self.dialect.tool_name_map.get(diversified_tool_name)
        if canonical_tool is None:
            raise UnknownToolError(diversified_tool_name)

        impl = self._implementations[canonical_tool]
        canonical_kwargs = {
            self.dialect.param_name_map.get((canonical_tool, key), key): value
            for key, value in diversified_kwargs.items()
        }
        return impl(**canonical_kwargs)
