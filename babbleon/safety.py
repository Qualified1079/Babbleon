"""Guards against the one mistake that defeats the whole toolkit:
letting `.babbleon/registry.json` (every decoy path + honeytoken value,
in plaintext) get tracked or committed into the repo it's protecting.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

REGISTRY_DIRNAME = ".babbleon"


def _run_git(root: Path, *args):
    return subprocess.run(
        ["git", "-C", str(root), *args],
        capture_output=True,
        text=True,
    )


def is_git_repo(root: Path) -> bool:
    result = _run_git(root, "rev-parse", "--is-inside-work-tree")
    return result.returncode == 0 and result.stdout.strip() == "true"


def git_dir(root: Path):
    result = _run_git(root, "rev-parse", "--git-dir")
    if result.returncode != 0:
        return None
    path = Path(result.stdout.strip())
    return path if path.is_absolute() else root / path


def is_ignored(root: Path, relpath: str) -> bool:
    result = _run_git(root, "check-ignore", "-q", relpath)
    return result.returncode == 0


def tracked_registry_paths(root: Path):
    result = _run_git(root, "ls-files", REGISTRY_DIRNAME)
    return [line for line in result.stdout.splitlines() if line.strip()]


def staged_registry_paths(root: Path):
    result = _run_git(root, "diff", "--cached", "--name-only")
    return [
        line
        for line in result.stdout.splitlines()
        if line.startswith(f"{REGISTRY_DIRNAME}/")
    ]


def check(root: Path) -> list:
    """Return human-readable problem strings; an empty list means clean."""
    if not is_git_repo(root):
        return []

    problems = []
    registry_exists = (root / REGISTRY_DIRNAME).exists()

    tracked = tracked_registry_paths(root)
    if tracked:
        shown = ", ".join(tracked[:5]) + (", ..." if len(tracked) > 5 else "")
        problems.append(
            f"{len(tracked)} file(s) under {REGISTRY_DIRNAME}/ are already "
            f"tracked by git: {shown}"
        )

    staged = staged_registry_paths(root)
    if staged:
        shown = ", ".join(staged[:5]) + (", ..." if len(staged) > 5 else "")
        problems.append(
            f"{len(staged)} file(s) under {REGISTRY_DIRNAME}/ are staged "
            f"for commit: {shown}"
        )

    # `git check-ignore` reports a path as *not* ignored once it's
    # already in the index, regardless of .gitignore content -- so this
    # check is only meaningful (and its advice only correct) when the
    # tracked/staged checks above didn't already explain what's wrong.
    if registry_exists and not tracked and not staged and not is_ignored(root, REGISTRY_DIRNAME):
        problems.append(
            f"{REGISTRY_DIRNAME}/ exists but is not gitignored -- "
            f"add it to .gitignore before committing"
        )

    return problems
