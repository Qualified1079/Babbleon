"""
View presentation: trusted-tier and untrusted-tier filesystem views.

M1: simulated via dict-based "view" objects over a sandbox directory.
M3: real mount-namespace bind mounts will live in babbleon.enforcement.namespace.
"""
import pathlib
from dataclasses import dataclass

from ..mapping import MappingTable


@dataclass(frozen=True)
class View:
    """A frozen view of {visible_name -> real_path} for one trust tier."""
    tier: str
    entries: dict[str, pathlib.Path]

    def names(self) -> list[str]:
        return sorted(self.entries.keys())

    def resolve(self, name: str) -> pathlib.Path | None:
        return self.entries.get(name)

    @classmethod
    def trusted(cls, real_names: list[str], real_root: pathlib.Path) -> "View":
        entries = {n: real_root / n for n in real_names if (real_root / n).exists()}
        return cls(tier="trusted", entries=entries)

    @classmethod
    def untrusted(cls, mapping: MappingTable, real_root: pathlib.Path) -> "View":
        entries: dict[str, pathlib.Path] = {}
        for real, scrambled in mapping.real_to_scrambled.items():
            p = real_root / real
            if p.exists():
                entries[scrambled] = p
        return cls(tier="untrusted", entries=entries)
