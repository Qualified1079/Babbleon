"""
Banner-spoofing wrapper: defeats `--help`/`strings`/`ldd` fingerprinting.

Per PLAN.md §2a-1, an attacker that knows Babbleon is running will
fingerprint binaries by content rather than name. The bind-mounted
scrambled name still points at the *real* binary, so `curl --help`
under a scrambled name returns curl's help text — the rename is theater.

This module generates a thin loader binary per scrambled name. The
loader:
  - exec's the real binary when called by a *trusted-tier* process
    (detected via parent PID's mount-namespace match, or a session cookie)
  - returns sanitized output for `--help`, `--version`, `-h`, `-V` when
    called by an untrusted-tier process
  - has stripped symbols + per-host random padding to defeat hash-ID

M3 baseline: null/empty banner output.
M3.5 deception: plausible-wrong banner from a small mapping table
(e.g. scrambled-curl returns nano's help).

REVIEW(manual): the trusted/untrusted detection mechanism is the hard
part. Options: (a) check /proc/self/ns/mnt against a known trusted NS
inode, (b) require a session cookie env var (defeated by env scrape),
(c) check parent process tree. (a) is the most robust; needs CAP_SYS_PTRACE
to read /proc/<other>/ns/* but our own /proc/self/ns/mnt is always readable.
"""

from __future__ import annotations

import hashlib
import os
import pathlib
import textwrap

WRAPPER_TEMPLATE = textwrap.dedent("""\
    #!/bin/sh
    # babbleon scrambled-binary wrapper — do not modify
    # padding: {padding}
    # generated for scrambled name: {scrambled}
    case "$1" in
        --help|--version|-h|-V|-help|-version)
            # M3 baseline: null output. M3.5 will substitute a plausible-wrong banner.
            exit 0
            ;;
    esac
    # In a real M3 build this checks the trust tier and exec's the real binary
    # only for trusted callers. The simulated build exec's unconditionally.
    exec {real_path} "$@"
""")


def _padding(scrambled: str, host_secret: bytes) -> str:
    """Per-host random comment bytes to make hash-fingerprinting useless."""
    h = hashlib.sha256(host_secret + scrambled.encode()).hexdigest()
    return h[:32]


def write_wrapper(scrambled_name: str,
                  real_path: pathlib.Path,
                  output_dir: pathlib.Path,
                  host_secret: bytes) -> pathlib.Path:
    """Generate a wrapper script for one scrambled name."""
    output_dir.mkdir(parents=True, exist_ok=True)
    wrapper_path = output_dir / scrambled_name
    contents = WRAPPER_TEMPLATE.format(
        padding=_padding(scrambled_name, host_secret),
        scrambled=scrambled_name,
        real_path=real_path,
    )
    wrapper_path.write_text(contents)
    wrapper_path.chmod(0o755)
    return wrapper_path


def write_all(mapping_iter, real_root: pathlib.Path,
              output_dir: pathlib.Path, host_secret: bytes) -> dict[str, pathlib.Path]:
    """
    Generate wrappers for every (real, scrambled) pair where the real
    binary exists under real_root.
    """
    out: dict[str, pathlib.Path] = {}
    for real, scrambled in mapping_iter:
        src = real_root / real
        if not src.exists():
            continue
        out[scrambled] = write_wrapper(scrambled, src, output_dir, host_secret)
    return out
