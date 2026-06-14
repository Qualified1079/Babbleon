"""
Platform detection and capability probes.

All platform-specific branching in the codebase should import from here,
not call os.uname() / sys.platform directly. This keeps hardware-specific
paths easy to audit and fake in tests.
"""

from __future__ import annotations

import os
import pathlib
import shutil
import sys


def current() -> str:
    """Return canonical platform identifier: 'linux', 'macos', 'windows', 'other'."""
    p = sys.platform
    if p.startswith("linux"):
        return "linux"
    if p == "darwin":
        return "macos"
    if p in ("win32", "cygwin"):
        return "windows"
    return "other"


def is_linux() -> bool:
    return current() == "linux"


def is_macos() -> bool:
    return current() == "macos"


# -- capability probes (lazy, cached) -----------------------------------------

_cache: dict[str, bool] = {}


def _probe(key: str, fn) -> bool:
    if key not in _cache:
        try:
            _cache[key] = bool(fn())
        except Exception:
            _cache[key] = False
    return _cache[key]


def has_unshare() -> bool:
    """True if CLONE_NEWNS unshare is likely to succeed (Linux + CAP_SYS_ADMIN)."""
    if not is_linux():
        return False
    return _probe("unshare", lambda: os.access("/proc/self/ns/mnt", os.R_OK))


def has_tpm2_tools() -> bool:
    return _probe("tpm2_tools", lambda: shutil.which("tpm2_getcap") is not None)


def has_proc_fs() -> bool:
    return _probe("proc", lambda: pathlib.Path("/proc/self/status").exists())


def kernel_version() -> tuple[int, int, int]:
    if not is_linux():
        return (0, 0, 0)
    r = os.uname().release.split("-")[0]
    parts = r.split(".")
    try:
        return tuple(int(p) for p in parts[:3])  # type: ignore[return-value]
    except ValueError:
        return (0, 0, 0)


def supports_landlock() -> bool:
    """Landlock requires kernel >= 5.13."""
    return is_linux() and kernel_version() >= (5, 13, 0)


def supports_ebpf_lsm() -> bool:
    """eBPF-LSM requires kernel >= 5.7 and lsm=...,bpf in cmdline."""
    if not is_linux() or kernel_version() < (5, 7, 0):
        return False
    return _probe("ebpf_lsm", _check_ebpf_lsm_boot_param)


def _check_ebpf_lsm_boot_param() -> bool:
    cmdline = pathlib.Path("/proc/cmdline")
    if not cmdline.exists():
        return False
    return "lsm=" in cmdline.read_text() and "bpf" in cmdline.read_text()


def clear_cache() -> None:
    """For tests: reset all cached probe results."""
    _cache.clear()
