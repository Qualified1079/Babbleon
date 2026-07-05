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

from .errors import BabbleonError

try:
    import fcntl
except ImportError:  # e.g. Windows -- no cross-process locking there;
    fcntl = None     # same race that existed everywhere before this fix.

DEFAULT_REGISTRY_DIR = ".babbleon"
DEFAULT_REGISTRY_FILE = "registry.json"
LOCK_FILE = ".lock"


class Registry:
    def __init__(self, root: Path):
        self.root = Path(root)
        self.dir = self.root / DEFAULT_REGISTRY_DIR
        self.file = self.dir / DEFAULT_REGISTRY_FILE
        self.entries = []
        self._lock_fh = None
        self._load()

    def _load(self):
        if not self.file.exists():
            self.entries = []
            return
        try:
            data = json.loads(self.file.read_text())
        except json.JSONDecodeError as e:
            # Don't silently treat this as an empty registry -- that would
            # make `list`/`verify`/`is-decoy` quietly forget about decoys
            # that are still sitting on disk. Fail loud with something
            # actionable instead of a bare JSONDecodeError traceback.
            raise BabbleonError(
                f"babbleon registry at {self.file} is not valid JSON ({e}). "
                f"It may have been partially written or hand-edited. Do not "
                f"delete it without first checking whether decoy files are "
                f"still on disk -- see handoff.md for what the registry is for."
            ) from e
        if not isinstance(data, dict):
            raise BabbleonError(
                f"babbleon registry at {self.file} is valid JSON but not a "
                f"babbleon registry (expected a JSON object, found a "
                f"{type(data).__name__}). Do not delete it without first "
                f"checking whether decoy files are still on disk."
            )
        entries = data.get("entries", [])
        if not isinstance(entries, list):
            raise BabbleonError(
                f"babbleon registry at {self.file} has a non-list 'entries' "
                f"field ({type(entries).__name__}) -- it doesn't look like a "
                f"babbleon registry. Do not delete it without first checking "
                f"whether decoy files are still on disk."
            )
        self.entries = entries

    def save(self):
        self.dir.mkdir(parents=True, exist_ok=True)
        payload = {"version": 1, "entries": self.entries}
        # write-then-rename so a crash mid-write can't leave a truncated
        # registry.json that _load() would choke on with a raw JSONDecodeError
        tmp_file = self.file.with_name(self.file.name + ".tmp")
        tmp_file.write_text(json.dumps(payload, indent=2, sort_keys=True))
        tmp_file.replace(self.file)

    def __enter__(self):
        """Hold an exclusive lock across a load-mutate-save cycle so two
        concurrent `seed`/`clean` invocations can't silently clobber each
        other's registry entries (last save wins otherwise, even though
        each process's decoy files are all still safely on disk)."""
        self.dir.mkdir(parents=True, exist_ok=True)
        if fcntl is not None:
            self._lock_fh = open(self.dir / LOCK_FILE, "w")
            fcntl.flock(self._lock_fh, fcntl.LOCK_EX)
        # Re-read now that we hold the lock -- another process may have
        # written since our unlocked __init__ load.
        self._load()
        return self

    def __exit__(self, exc_type, exc, tb):
        try:
            # Always save, even on exception -- a decoy pack that already
            # wrote its file to disk before a later pack failed still
            # needs to be registered (see cmd_seed's history).
            self.save()
        finally:
            if self._lock_fh is not None:
                fcntl.flock(self._lock_fh, fcntl.LOCK_UN)
                self._lock_fh.close()
                self._lock_fh = None
        return False

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
        absolute = p if p.is_absolute() else (self.root / p)
        try:
            rel = str(absolute.resolve().relative_to(self.root.resolve()))
        except ValueError:
            return False
        return rel in self.paths()
