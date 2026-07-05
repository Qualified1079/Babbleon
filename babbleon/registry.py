"""JSON-backed ledger of every decoy/honeytoken babbleon has planted.

Lets a maintainer tell decoys apart from real files, and trace a leaked
string back to the decoy it came from.

SECURITY NOTE: this file stores every honeytoken value in plaintext. It
is gitignored by default and must never be committed into the same repo
it is protecting -- anyone (human or agent) who can read the registry
gets the full list of decoys and defeats the trap. Keep it local, or
back it up somewhere separate from the seeded repo.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

DEFAULT_REGISTRY_DIR = ".babbleon"
DEFAULT_REGISTRY_FILE = "registry.json"


class Registry:
    def __init__(self, root: Path):
        self.root = Path(root)
        self.dir = self.root / DEFAULT_REGISTRY_DIR
        self.file = self.dir / DEFAULT_REGISTRY_FILE
        self.entries = []
        self._load()

    def _load(self):
        if self.file.exists():
            data = json.loads(self.file.read_text())
            self.entries = data.get("entries", [])
        else:
            self.entries = []

    def save(self):
        self.dir.mkdir(parents=True, exist_ok=True)
        payload = {"version": 1, "entries": self.entries}
        self.file.write_text(json.dumps(payload, indent=2, sort_keys=True))

    def add(self, path: str, pack: str, tokens: list) -> dict:
        entry = {
            "path": path,
            "pack": pack,
            "created_at": time.time(),
            "tokens": [t.to_dict() for t in tokens],
        }
        self.entries.append(entry)
        return entry

    def all_tokens(self):
        for entry in self.entries:
            for t in entry["tokens"]:
                yield entry, t

    def find_by_value_substring(self, needle: str):
        if not needle:
            return []
        return [
            (entry, t)
            for entry, t in self.all_tokens()
            if needle in t["value"] or needle == t["id"]
        ]

    def paths(self):
        return [e["path"] for e in self.entries]

    def is_decoy(self, path) -> bool:
        """Is `path` (absolute or repo-relative) a planted decoy?

        Meant for a legitimate tool -- a security scanner, a coding
        assistant -- running *inside* the same repo to check before
        treating something it found as a real issue. Decoys are built to
        look like real attack surface to any agent reading the tree,
        which includes a benign one doing routine work; this is the
        escape hatch for that case (see handoff.md, "decoys vs.
        legitimate tooling").
        """
        p = Path(path)
        if p.is_absolute():
            try:
                rel = str(p.resolve().relative_to(self.root.resolve()))
            except ValueError:
                return False
        else:
            rel = str(p)
        return rel in self.paths()
