"""
Raw Linux syscall wrappers via ctypes.

Isolated here so the rest of the enforcement layer has no ctypes
imports. Never import this module on non-Linux platforms.

All functions raise EnforcementError on failure with a human-readable
errno message. They do NOT handle capability checks — that's the
caller's responsibility.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import os

from ..errors import EnforcementError

# Clone flags (<linux/sched.h>)
CLONE_NEWNS  = 0x00020000
CLONE_NEWPID = 0x20000000

# Mount flags (<sys/mount.h>)
MS_BIND    = 0x1000
MS_PRIVATE = 0x40000
MS_REC     = 0x4000
UMOUNT_FORCE = 1


def _libc() -> ctypes.CDLL:
    name = ctypes.util.find_library("c")
    if not name:
        raise EnforcementError("libc not found")
    return ctypes.CDLL(name, use_errno=True)


_lib: ctypes.CDLL | None = None


def _get_lib() -> ctypes.CDLL:
    global _lib
    if _lib is None:
        _lib = _libc()
    return _lib


def unshare(flags: int) -> None:
    if _get_lib().unshare(flags) != 0:
        err = ctypes.get_errno()
        raise EnforcementError(f"unshare(0x{flags:x}) failed: {os.strerror(err)}")


def mount(source: str, target: str, fstype: str | None,
          flags: int, data: str = "") -> None:
    lib = _get_lib()
    rc = lib.mount(
        source.encode(),
        target.encode(),
        fstype.encode() if fstype else None,
        flags,
        data.encode() if data else None,
    )
    if rc != 0:
        err = ctypes.get_errno()
        raise EnforcementError(
            f"mount({source!r} -> {target!r}) failed: {os.strerror(err)}"
        )


def umount2(target: str, flags: int = UMOUNT_FORCE) -> None:
    if _get_lib().umount2(target.encode(), flags) != 0:
        err = ctypes.get_errno()
        raise EnforcementError(f"umount2({target!r}) failed: {os.strerror(err)}")
