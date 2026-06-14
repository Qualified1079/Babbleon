"""
LinuxNamespaceDriver: mount + PID namespace enforcement.

Consumes _syscalls for all kernel calls; no ctypes here.
Hardware-agnostic at the class level — platform check happens in the
factory (enforcement/factory.py), not here.

Architecture:
  present_trusted()   — pass-through, no kernel work
  present_untrusted() — tmpfs at scrambled_root, one bind-mount per tool,
                        /proc remounted with hidepid=2

Deferred work (see DEFERRED.md):
  - setuid helper for CAP_SYS_ADMIN boundary
  - PID NS + tini as init (DEFERRED M3.5)
  - seccomp-bpf filter (DEFERRED M3)
  - Landlock self-sandbox (DEFERRED M3)
"""

from __future__ import annotations

import pathlib

from ..errors import EnforcementError
from ..mapping import MappingTable
from ._syscalls import (
    CLONE_NEWNS, CLONE_NEWPID,
    MS_BIND, MS_PRIVATE, MS_REC,
    mount, umount2, unshare,
)
from .driver import EnforcementResult
from .views import View


class LinuxNamespaceDriver:
    name = "linux-ns"

    def __init__(self, scrambled_root: pathlib.Path | None = None) -> None:
        self.scrambled_root = scrambled_root or pathlib.Path("/var/lib/babbleon/scrambled")
        self._mounts: list[pathlib.Path] = []

    def present_trusted(self,
                        real_root: pathlib.Path,
                        tracked: list[str]) -> EnforcementResult:
        view = View.trusted(tracked, real_root)
        return EnforcementResult(
            tier="trusted",
            visible=dict(view.entries),
            notes=[f"trusted: pass-through {real_root}"],
        )

    def present_untrusted(self,
                          real_root: pathlib.Path,
                          mapping: MappingTable) -> EnforcementResult:
        """
        Materialize untrusted view in the current mount namespace.

        Caller must already be in a fresh CLONE_NEWNS namespace.
        See launcher.py for the fork-unshare-exec wrapper.
        """
        self.scrambled_root.mkdir(parents=True, exist_ok=True)

        # isolate this NS from the host so our mounts don't propagate
        try:
            mount("none", "/", None, MS_PRIVATE | MS_REC)
        except EnforcementError as exc:
            raise EnforcementError(
                f"cannot set mount propagation private ({exc}). "
                "Is the caller in a fresh CLONE_NEWNS namespace?"
            ) from exc

        mount("tmpfs", str(self.scrambled_root), "tmpfs", 0, "mode=0755")
        self._mounts.append(self.scrambled_root)

        visible: dict[str, pathlib.Path] = {}
        for real, scrambled in mapping.real_to_scrambled.items():
            src = real_root / real
            if not src.exists():
                continue
            dst = self.scrambled_root / scrambled
            dst.touch(mode=0o755)
            mount(str(src), str(dst), None, MS_BIND)
            self._mounts.append(dst)
            visible[scrambled] = dst

        # /proc hidepid: only effective inside a fresh PID NS.
        # Silently skipped when PID NS isn't set up — see DEFERRED.md.
        try:
            mount("proc", "/proc", "proc", 0, "hidepid=2")
        except EnforcementError:
            pass

        return EnforcementResult(
            tier="untrusted",
            visible=visible,
            notes=[f"{len(visible)} bind mounts at {self.scrambled_root}"],
        )

    def teardown(self) -> None:
        for path in reversed(self._mounts):
            try:
                umount2(str(path))
            except EnforcementError:
                pass
        self._mounts.clear()
