"""
Launcher: set up an untrusted-tier subprocess.

Handles the namespace dance:
  1. Fork a child.
  2. Child: unshare CLONE_NEWNS | CLONE_NEWPID.
  3. Child: re-exec a small init (or self) that becomes PID 1.
  4. Init: invoke driver.present_untrusted().
  5. Init: exec target command with PATH adjusted to scrambled_root.

For M3 we ship a minimal init-as-self pattern; tini integration is M3.5.

REVIEW(manual): the launcher currently calls os.fork()+os.execv() directly;
production should use a small C helper to avoid Python interpreter overhead
at the namespace boundary. Spawning Python under PID 1 also makes signal
handling fiddly.

REVIEW(manual): CAP_SYS_ADMIN requirement — this launcher only works as
root or with a CAP_SYS_ADMIN-granting setuid helper. The PAM module
(pam_babbleon.so, future) is the production lifecycle.
"""

from __future__ import annotations

import os
import pathlib

from ..errors import EnforcementError
from ..mapping import MappingTable
from .driver import EnforcementDriver
from .linux_ns import CLONE_NEWNS, CLONE_NEWPID, LinuxNamespaceDriver


def launch_untrusted(
    driver: EnforcementDriver,
    real_root: pathlib.Path,
    mapping: MappingTable,
    argv: list[str],
    extra_env: dict[str, str] | None = None,
) -> int:
    """
    Spawn `argv` in an untrusted-tier subprocess. Returns child exit code.

    Synchronous: blocks until child exits. The parent process retains
    its trusted view; only the child sees the scrambled namespace.
    """
    if os.uname().sysname != "Linux":
        raise EnforcementError("launch_untrusted requires Linux")

    pid = os.fork()
    if pid == 0:
        try:
            if isinstance(driver, LinuxNamespaceDriver):
                # need CAP_SYS_ADMIN to do this
                import ctypes
                libc = ctypes.CDLL("libc.so.6", use_errno=True)
                if libc.unshare(CLONE_NEWNS | CLONE_NEWPID) != 0:
                    err = ctypes.get_errno()
                    os._exit(_fatal(f"unshare failed: {os.strerror(err)}"))

            result = driver.present_untrusted(real_root, mapping)
            env = os.environ.copy()
            env["PATH"] = f"{result.visible and next(iter(result.visible.values())).parent}:{env.get('PATH', '')}"
            if extra_env:
                env.update(extra_env)
            os.execvpe(argv[0], argv, env)
        except Exception as exc:
            os._exit(_fatal(str(exc)))
        os._exit(127)
    else:
        _, status = os.waitpid(pid, 0)
        return os.WEXITSTATUS(status) if os.WIFEXITED(status) else 1


def _fatal(msg: str) -> int:
    os.write(2, f"[babbleon-launcher] fatal: {msg}\n".encode())
    return 1
