"""
SimulatedDriver: no-op enforcement.

Returns dict-based views without touching the kernel. Used by:
- M1 sandbox demo
- Test suites on all platforms
- Cross-platform fallback when no real driver is available

Pairs with View.trusted / View.untrusted.
"""

from __future__ import annotations

import pathlib

from ..mapping import MappingTable
from .driver import EnforcementResult
from .views import View


class SimulatedDriver:
    """In-memory view materialization. No kernel calls."""

    name = "simulated"

    def present_trusted(self,
                        real_root: pathlib.Path,
                        tracked: list[str]) -> EnforcementResult:
        view = View.trusted(tracked, real_root)
        return EnforcementResult(
            tier="trusted",
            visible=dict(view.entries),
            notes=[f"simulated trusted view over {real_root}"],
        )

    def present_untrusted(self,
                          real_root: pathlib.Path,
                          mapping: MappingTable) -> EnforcementResult:
        view = View.untrusted(mapping, real_root)
        return EnforcementResult(
            tier="untrusted",
            visible=dict(view.entries),
            notes=[
                f"simulated untrusted view over {real_root}",
                f"{len(view.entries)} scrambled names",
            ],
        )

    def teardown(self) -> None:
        return None
