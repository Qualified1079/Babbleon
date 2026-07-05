"""A narrow, dedicated exception type for babbleon's own expected,
actionable failures (a corrupted registry, a collision budget exhausted).

Deliberately NOT just `RuntimeError` -- `RecursionError` and other
unrelated stdlib/programming-bug exceptions are `RuntimeError` subclasses
too, so catching plain `RuntimeError` at the CLI's top level would
silently disguise a genuine bug as a clean "error: ..." message and
throw away the traceback that would have pointed at it.
"""

from __future__ import annotations


class BabbleonError(RuntimeError):
    pass
