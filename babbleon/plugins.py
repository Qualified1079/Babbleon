"""
Plugin registry: enterprise extensions slot in here without touching
the public codebase.

Extension points (all use Python entry_points under group "babbleon.*"):

  babbleon.vault_backends   — additional KEK backends (HSM, Vault by HashiCorp,
                              SCIM-backed, escrow-server)
  babbleon.event_sinks      — audit/detection event consumers (SIEM, syslog,
                              webhook, central escrow server)
  babbleon.enforcement      — namespace backend drivers (fleet-policy-aware
                              mount NS manager, Windows minifilter, macOS ES)
  babbleon.manifest_sources — manifest providers (MDM-pushed tool list,
                              fleet-policy tool inventory)

Enterprise package convention: ship as `babbleon-enterprise` and declare
entry_points in its pyproject.toml. The public package loads them here at
runtime; no public-package code changes required.

Usage (public package, community extensions, enterprise extensions alike):

    registry = PluginRegistry.load()
    backend = registry.vault_backend("hsm")   # raises KeyError if not installed
"""

from __future__ import annotations

import importlib.metadata
import logging
from typing import Any

log = logging.getLogger(__name__)

_GROUPS = {
    "vault_backends": "babbleon.vault_backends",
    "event_sinks": "babbleon.event_sinks",
    "enforcement": "babbleon.enforcement",
    "manifest_sources": "babbleon.manifest_sources",
}


class PluginRegistry:
    def __init__(self, plugins: dict[str, dict[str, Any]]) -> None:
        self._p = plugins

    @classmethod
    def load(cls) -> "PluginRegistry":
        discovered: dict[str, dict[str, Any]] = {k: {} for k in _GROUPS}
        for attr_name, group in _GROUPS.items():
            try:
                eps = importlib.metadata.entry_points(group=group)
            except Exception:
                continue
            for ep in eps:
                try:
                    discovered[attr_name][ep.name] = ep.load()
                    log.debug("loaded plugin %s/%s", group, ep.name)
                except Exception as exc:
                    log.warning("failed to load plugin %s/%s: %s", group, ep.name, exc)
        return cls(discovered)

    def vault_backend(self, name: str) -> Any:
        return self._p["vault_backends"][name]

    def event_sinks(self) -> list[Any]:
        return list(self._p["event_sinks"].values())

    def enforcement_backend(self, name: str) -> Any:
        return self._p["enforcement"][name]

    def manifest_source(self, name: str) -> Any:
        return self._p["manifest_sources"][name]

    def available(self, group: str) -> list[str]:
        return list(self._p.get(group, {}).keys())
