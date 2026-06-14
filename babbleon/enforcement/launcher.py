"""
Untrusted-tier subprocess launcher (Linux).

Lifecycle:
  1. Fork.
  2. Child: unshare(CLONE_NEWNS | CLONE_NEWPID) via _syscalls.
  3. Child: call driver.present_untrusted() to set up bind mounts.
  4. Child: exec target command with PATH prepended with scrambled_root.
  5. Parent: wait, return exit code.

This module has NO ctypes imports; all kernel calls go through _syscalls.

Deferred (DEFERRED.md):
  - setuid C helper to avoid Python holding CAP_SYS_ADMIN
  - tini as PID-1 init for correct signal + zombie handling (M3.5)
  - PAM module lifecycle (M3)
"""

from __future__ import annotations

import os
import pathlib

from .. import platform as plt
from ..errors import EnforcementError
from ..mapping import MappingTable
from ._syscalls import CLONE_NEWNS, CLONE_NEWPID, unshare
from .driver import EnforcementDriver


def launch_untrusted(
    driver: EnforcementDriver,
    real_root: pathlib.Path,
    mapping: MappingTable,
    argv: list[str],
    extra_env: dict[str, str] | None = None,
) -> int:
    """
    Run `argv` in an untrusted-tier subprocess. Returns child exit code.

    Parent process retains its trusted view. Blocks until child exits.
    Raises EnforcementError if not on Linux.
    """
    if not plt.is_linux():
        raise EnforcementError("launch_untrusted is Linux-only")

    pid = os.fork()
    if pid == 0:
        _child(driver, real_root, mapping, argv, extra_env or {})
        os._exit(127)  # unreachable if exec succeeds
    else:
        _, status = os.waitpid(pid, 0)
        return os.WEXITSTATUS(status) if os.WIFEXITED(status) else 1


def _child(driver: EnforcementDriver,
           real_root: pathlib.Path,
           mapping: MappingTable,
           argv: list[str],
           extra_env: dict[str, str]) -> None:
    """Runs in the forked child; never returns normally."""
    try:
        unshare(CLONE_NEWNS | CLONE_NEWPID)
    except EnforcementError as exc:
        _fatal(f"unshare failed: {exc}")
        return

    try:
        result = driver.present_untrusted(real_root, mapping)
    except EnforcementError as exc:
        _fatal(f"view setup failed: {exc}")
        return

    env = os.environ.copy()
    if result.visible:
        scrambled_bin = next(iter(result.visible.values())).parent
        env["PATH"] = f"{scrambled_bin}:{env.get('PATH', '')}"
    env.update(extra_env)

    try:
        os.execvpe(argv[0], argv, env)
    except OSError as exc:
        _fatal(f"exec {argv[0]!r} failed: {exc}")


def _fatal(msg: str) -> None:
    os.write(2, f"[babbleon-launcher] {msg}\n".encode())
    os._exit(1)
