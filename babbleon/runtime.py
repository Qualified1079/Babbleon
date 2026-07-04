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


class MalformedCallError(ValueError):
    """Raised when an incoming call's shape doesn't match this dialect's
    calling convention (see `dialect._calling_convention`).

    Distinct from `UnknownToolError`: the caller got the tool/param names
    right but assumed the wrong call shape (e.g. flat kwargs against a
    "wrapped" install) --- exactly what a worm that already has your
    renamed identifiers, but not your calling convention, would trip.
    """


class DialectRuntime:
    def __init__(self, dialect: Dialect, implementations: Dict[str, Callable[..., Any]]):
        self.dialect = dialect
        self._implementations = implementations

    @property
    def surface(self):
        return self.dialect.surface

    def dispatch(self, diversified_tool_name: str, diversified_kwargs: Dict[str, Any]) -> Any:
        """Translate an already-unwrapped, flat diversified kwargs dict to
        the canonical implementation. Calling-convention-agnostic --- use
        `dispatch_raw` when the caller's call shape hasn't been unwrapped
        yet and might not match this dialect's convention at all.
        """
        canonical_tool = self.dialect.tool_name_map.get(diversified_tool_name)
        if canonical_tool is None:
            raise UnknownToolError(diversified_tool_name)

        impl = self._implementations[canonical_tool]
        canonical_kwargs = {
            self.dialect.param_name_map.get((canonical_tool, key), key): value
            for key, value in diversified_kwargs.items()
        }
        return impl(**canonical_kwargs)

    def dispatch_raw(self, diversified_tool_name: str, raw_call: Dict[str, Any]) -> Any:
        """Convention-aware entry point: unwraps `raw_call` per this
        dialect's `calling_convention` before delegating to `dispatch`.

        A caller (or a worm) that assumes the wrong shape gets
        `MalformedCallError`, not a silently-wrong dispatch --- shape
        mismatches must fail closed.
        """
        if self.dialect.calling_convention == "wrapped":
            if set(raw_call.keys()) != {self.dialect.wrapper_key}:
                raise MalformedCallError(
                    f"expected a single wrapper key {self.dialect.wrapper_key!r}, "
                    f"got keys {sorted(raw_call.keys())}"
                )
            inner = raw_call[self.dialect.wrapper_key]
            if not isinstance(inner, dict):
                raise MalformedCallError(
                    f"expected wrapper key {self.dialect.wrapper_key!r} to contain an "
                    f"object, got {type(inner).__name__}"
                )
            return self.dispatch(diversified_tool_name, inner)

        if self.dialect.wrapper_key and self.dialect.wrapper_key in raw_call:
            raise MalformedCallError(
                "flat convention expected, but call is wrapped under "
                f"{self.dialect.wrapper_key!r}"
            )
        return self.dispatch(diversified_tool_name, raw_call)
