"""
Tool manifest: the list of real names that Babbleon tracks per host.

Community edition: static default list, or a local TOML file.
Enterprise extension: MDM-pushed manifest, fleet-policy inventory,
per-team override — loaded via the babbleon.manifest_sources entry_point.

Manifest format (TOML):
  [manifest]
  version = 1
  tracked = ["curl", "ssh", ...]
  # optional: per-tool metadata (enterprise only)
  [tools.curl]
  tier = "must"
  credential_env = []
"""

from __future__ import annotations

import pathlib

try:
    import tomllib
except ImportError:
    import tomli as tomllib  # type: ignore[no-redef]  # Python <3.11 fallback


DEFAULT_TRACKED: list[str] = [
    "curl", "ssh", "nc", "python3", "bash", "wget", "git",
    "aws", "gh", "kubectl", "docker", "terraform", "npm", "pip",
]


class Manifest:
    def __init__(self, tracked: list[str]) -> None:
        self.tracked = tracked

    @classmethod
    def default(cls) -> "Manifest":
        return cls(tracked=list(DEFAULT_TRACKED))

    @classmethod
    def from_file(cls, path: pathlib.Path) -> "Manifest":
        data = tomllib.loads(path.read_text())
        tracked = data.get("manifest", {}).get("tracked", DEFAULT_TRACKED)
        return cls(tracked=tracked)

    @classmethod
    def load(cls, path: pathlib.Path | None = None) -> "Manifest":
        """Load from file if present, otherwise use defaults."""
        if path and path.exists():
            return cls.from_file(path)
        return cls.default()
