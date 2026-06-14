"""
EnforcementDriver protocol: how a view is *materialized* on the host.

Implementations:
  SimulatedDriver       — in-memory dict view, no system changes (M1/tests)
  LinuxNamespaceDriver  — mount + PID namespaces, bind mounts (M3)
  MacOSDriver           — Endpoint Security framework (M5+, future)
  WindowsDriver         — minifilter (v3+, research)
  FleetDriver           — enterprise: policy-aware mount NS over a fleet

The public Session selects a driver via the babbleon.enforcement entry_point
group, or instantiates SimulatedDriver as a no-op default.
"""

from __future__ import annotations

import pathlib
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from ..mapping import MappingTable


@dataclass
class EnforcementResult:
    """What a driver tells the caller after presenting a view."""
    tier: str           # "trusted" or "untrusted"
    visible: dict[str, pathlib.Path]
    notes: list[str]    # human-readable diagnostics


@runtime_checkable
class EnforcementDriver(Protocol):
    """
    Materialize a view of the host filesystem for one trust tier.

    `present` is called once per process tier at session start.
    Drivers may be no-ops (SimulatedDriver) or do real kernel work
    (LinuxNamespaceDriver: CLONE_NEWNS, bind mounts, /proc remount).
    """

    name: str

    def present_trusted(self,
                        real_root: pathlib.Path,
                        tracked: list[str]) -> EnforcementResult: ...

    def present_untrusted(self,
                          real_root: pathlib.Path,
                          mapping: MappingTable) -> EnforcementResult: ...

    def teardown(self) -> None:
        """Optional cleanup; safe to no-op."""
        ...
