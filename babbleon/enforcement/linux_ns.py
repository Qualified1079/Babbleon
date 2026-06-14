"""
LinuxNamespaceDriver: real mount + PID namespaces, bind mounts.

Architecture (per PLAN.md §8):
1. Unshare CLONE_NEWNS + CLONE_NEWPID; set propagation to private.
2. For untrusted tier: create a tmpfs at /var/lib/babbleon/scrambled,
   bind-mount each real binary to its scrambled name inside that tmpfs,
   then bind-mount the tmpfs over /usr/local/babbleon-bin (on PATH).
3. Remount /proc with hidepid=2,gid=proc.
4. Drop into target shell or exec target command.

This module is the *driver*; the actual root-required orchestration lives
behind a setuid helper or PAM module (babbleon-pam, M3 deliverable).

REVIEW(manual): the unshare/mount syscalls require CAP_SYS_ADMIN in the
caller's namespace. Plan: invoke via a small setuid binary that drops
privileges immediately after the syscalls. Do NOT keep this code path
runnable as root for any longer than needed.

REVIEW(manual): bind-mount-per-binary is O(N) syscalls at session start.
For N=200 tools this is ~50ms; acceptable. For N=2000 (enterprise tool
inventory) revisit — may want a FUSE overlay or a single bind of a
pre-prepared directory.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import os
import pathlib

from ..errors import EnforcementError
from ..mapping import MappingTable
from .driver import EnforcementResult
from .views import View

# Linux clone flags (from <linux/sched.h>); only valid on Linux.
CLONE_NEWNS = 0x00020000
CLONE_NEWPID = 0x20000000

# mount flags (from <sys/mount.h>)
MS_BIND = 0x1000
MS_PRIVATE = 0x40000
MS_REC = 0x4000


def _libc():
    name = ctypes.util.find_library("c")
    if not name:
        raise EnforcementError("libc not found; not on a glibc/musl system?")
    return ctypes.CDLL(name, use_errno=True)


def _check_linux():
    if os.uname().sysname != "Linux":
        raise EnforcementError("LinuxNamespaceDriver requires Linux")


class LinuxNamespaceDriver:
    """
    Real mount-namespace driver. Requires CAP_SYS_ADMIN.

    Typical lifecycle:
      driver = LinuxNamespaceDriver(scrambled_root=Path("/var/lib/babbleon/scrambled"))
      result = driver.present_untrusted(real_root=Path("/usr/bin"), mapping=table)
      # ... exec untrusted shell ...
      driver.teardown()
    """

    name = "linux-ns"

    def __init__(self, scrambled_root: pathlib.Path | None = None) -> None:
        _check_linux()
        self.scrambled_root = scrambled_root or pathlib.Path("/var/lib/babbleon/scrambled")
        self._libc = _libc()
        self._mounts: list[pathlib.Path] = []

    # -- syscall wrappers -----------------------------------------------------

    def _unshare(self, flags: int) -> None:
        if self._libc.unshare(flags) != 0:
            err = ctypes.get_errno()
            raise EnforcementError(f"unshare failed: {os.strerror(err)}")

    def _mount(self, source: str, target: str, fstype: str, flags: int, data: str = "") -> None:
        rc = self._libc.mount(
            source.encode(), target.encode(),
            fstype.encode() if fstype else None,
            flags, data.encode() if data else None,
        )
        if rc != 0:
            err = ctypes.get_errno()
            raise EnforcementError(f"mount({source} -> {target}) failed: {os.strerror(err)}")

    # -- public API -----------------------------------------------------------

    def present_trusted(self,
                        real_root: pathlib.Path,
                        tracked: list[str]) -> EnforcementResult:
        """Trusted view: no namespace work; pass-through real paths."""
        view = View.trusted(tracked, real_root)
        return EnforcementResult(
            tier="trusted",
            visible=dict(view.entries),
            notes=[f"trusted view: pass-through {real_root}"],
        )

    def present_untrusted(self,
                          real_root: pathlib.Path,
                          mapping: MappingTable) -> EnforcementResult:
        """
        Untrusted view: create scrambled bind mounts inside a new mount NS.

        Caller MUST be in a fresh mount namespace already (we don't unshare
        here because that would isolate the parent's view too). The setuid
        helper / PAM module handles the unshare before invoking this.
        """
        self.scrambled_root.mkdir(parents=True, exist_ok=True)

        # mark mount NS private to prevent propagation back to host
        try:
            self._mount("none", "/", "", MS_PRIVATE | MS_REC)
        except EnforcementError as exc:
            raise EnforcementError(
                f"could not set mount propagation private: {exc}; "
                "are we in a fresh mount namespace?"
            )

        # mount tmpfs as the scrambled root
        self._mount("tmpfs", str(self.scrambled_root), "tmpfs", 0, "mode=0755")
        self._mounts.append(self.scrambled_root)

        visible: dict[str, pathlib.Path] = {}
        for real, scrambled in mapping.real_to_scrambled.items():
            src = real_root / real
            if not src.exists():
                continue
            dst = self.scrambled_root / scrambled
            dst.touch(mode=0o755)
            self._mount(str(src), str(dst), "", MS_BIND)
            self._mounts.append(dst)
            visible[scrambled] = dst

        # /proc with hidepid=2; only effective if we're in a fresh PID NS too
        # REVIEW(manual): hidepid=2 mount may fail on non-fresh /proc; the
        # setuid helper must have established a fresh PID NS via unshare(CLONE_NEWPID)
        # and forked an init before reaching this point.
        try:
            self._mount("proc", "/proc", "proc", 0, "hidepid=2")
        except EnforcementError:
            pass  # not fatal in M3; PID NS handler is the proper fix

        return EnforcementResult(
            tier="untrusted",
            visible=visible,
            notes=[
                f"untrusted view: {len(visible)} bind mounts under {self.scrambled_root}",
                "PATH must include the scrambled_root for the shell to find names",
            ],
        )

    def teardown(self) -> None:
        """
        Best-effort unmount. In practice, namespace exit handles cleanup;
        this is for the case where the driver is reused in a long-running process.
        """
        UMOUNT_FORCE = 1
        for path in reversed(self._mounts):
            try:
                self._libc.umount2(str(path).encode(), UMOUNT_FORCE)
            except Exception:
                pass
        self._mounts.clear()
