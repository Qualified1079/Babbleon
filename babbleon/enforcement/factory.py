"""
Driver factory: select the right EnforcementDriver for this platform.

Call `default_driver()` to get the best available driver without knowing
anything about the platform. The selection order is:

  1. Any driver registered via the babbleon.enforcement entry_point (enterprise).
  2. LinuxNamespaceDriver if on Linux and namespaces are available.
  3. SimulatedDriver as an unconditional fallback.

The simulated fallback is intentional: it lets the rest of the code (tests,
demo, cross-platform dev) work without kernel support. Callers that *require*
real enforcement must explicitly check result.driver.name != 'simulated'.
"""

from __future__ import annotations

from .. import platform as plt
from ..plugins import PluginRegistry
from .driver import EnforcementDriver
from .simulated import SimulatedDriver


def default_driver(registry: PluginRegistry | None = None) -> EnforcementDriver:
    """Return the best available driver for this platform."""

    # 1. Enterprise override via plugin registry
    if registry:
        names = registry.available("enforcement")
        if names:
            return registry.enforcement_backend(names[0])

    # 2. Linux native
    if plt.is_linux() and plt.has_unshare():
        try:
            from .linux_ns import LinuxNamespaceDriver
            return LinuxNamespaceDriver()
        except Exception:
            pass

    # 3. Unconditional fallback
    return SimulatedDriver()


def driver_for(name: str) -> EnforcementDriver:
    """Explicit driver selection by name; raises KeyError if unavailable."""
    options: dict[str, type] = {
        "simulated": SimulatedDriver,
    }
    if plt.is_linux():
        from .linux_ns import LinuxNamespaceDriver
        options["linux-ns"] = LinuxNamespaceDriver

    if name not in options:
        raise KeyError(f"driver '{name}' unavailable on this platform ({plt.current()})")
    return options[name]()
