"""
Babbleon: per-host randomized namespace obfuscation.

Public API surface (stable; semver-governed):
  babbleon.session.Session          — lifecycle: init / unlock / rotate
  babbleon.mapping.MappingTable     — scramble / reveal / is_honey
  babbleon.enforcement.View         — trusted_view / untrusted_view
  babbleon.events.EventBus          — emit / add_sink / named helpers
  babbleon.manifest.Manifest        — tracked tool list
  babbleon.errors.*                 — exception hierarchy
  babbleon.vault.backend.KEKBackend — backend protocol (implement to add tiers)

Enterprise extension points (plugin registry via entry_points):
  babbleon.vault_backends    — additional KEK backends (HSM, escrow-server,
                               HashiCorp Vault, SCIM-backed)
  babbleon.event_sinks       — audit/detection consumers (SIEM, syslog,
                               webhook, central alert)
  babbleon.enforcement       — namespace driver backends (fleet-policy-aware
                               mount NS manager, Windows minifilter, macOS ES)
  babbleon.manifest_sources  — manifest providers (MDM-push, fleet policy)

Enterprise package convention: ship as `babbleon-enterprise` and declare
the entry_points in its pyproject.toml. No changes to this package required.
See babbleon.plugins.PluginRegistry for the loader.
"""

__version__ = "0.1.0"
