"""
Backend factory: select the right KEKBackend for this platform and tier.

Tier names match PLAN.md §7:
  'soft'     — Argon2id passphrase (always available)
  'usb'      — keyfile on removable media
  'tpm'      — TPM2 PCR sealing (Linux with tpm2-tools)
  'fido2'    — FIDO2 hmac-secret (requires python-fido2 + token)
  '<custom>' — enterprise backends from babbleon.vault_backends entry_point

`best_available()` selects the strongest tier present on this host.
`for_tier()` is explicit; raises if the tier is unavailable.

Hardware backends are never imported at module level — only inside the
function that selects them. This keeps the public package importable on
any platform without optional deps installed.
"""

from __future__ import annotations

import pathlib

from .. import platform as plt
from ..errors import HardwareUnavailable
from ..plugins import PluginRegistry
from .backend import KEKBackend
from .soft import SoftBackend


def best_available(keyfile_path: pathlib.Path | None = None,
                   registry: PluginRegistry | None = None) -> KEKBackend:
    """
    Return the strongest KEK backend available on this host.
    Hardware < USB < Soft (in ascending weakness order).
    Caller still needs to supply credentials at seal/unseal time.
    """
    # 1. Enterprise backends win if present
    if registry:
        names = registry.available("vault_backends")
        if names:
            return registry.vault_backend(names[0])

    # 2. FIDO2 (strongest; requires physical token present)
    try:
        b = _try_fido2()
        if b:
            return b
    except Exception:
        pass

    # 3. TPM
    if plt.has_tpm2_tools():
        try:
            from .tpm import TPMBackend
            if TPMBackend.available():
                return TPMBackend()
        except Exception:
            pass

    # 4. USB keyfile
    if keyfile_path and keyfile_path.exists():
        from .usb import USBBackend
        return USBBackend(keyfile_path)

    # 5. Always-available soft fallback
    return SoftBackend()


def for_tier(tier: str,
             keyfile_path: pathlib.Path | None = None,
             registry: PluginRegistry | None = None) -> KEKBackend:
    """Explicit tier selection. Raises HardwareUnavailable if tier is absent."""
    if registry:
        names = registry.available("vault_backends")
        if tier in names:
            return registry.vault_backend(tier)

    if tier == "soft":
        return SoftBackend()

    if tier == "usb":
        if not keyfile_path:
            raise HardwareUnavailable("usb tier requires keyfile_path")
        from .usb import USBBackend
        return USBBackend(keyfile_path)

    if tier == "tpm":
        if not plt.has_tpm2_tools():
            raise HardwareUnavailable("tpm2-tools not found; install tpm2-tools")
        from .tpm import TPMBackend
        if not TPMBackend.available():
            raise HardwareUnavailable("no TPM2 device accessible")
        return TPMBackend()

    if tier == "fido2":
        b = _try_fido2()
        if b is None:
            raise HardwareUnavailable(
                "no FIDO2 token present or python-fido2 not installed"
            )
        return b

    raise KeyError(f"unknown tier: {tier!r}")


def _try_fido2() -> KEKBackend | None:
    try:
        from .fido2 import FIDO2Backend
        from fido2.hid import CtapHidDevice
        devs = list(CtapHidDevice.list_devices())
        if devs:
            # REVIEW(manual): credential_id must come from enrollment;
            # placeholder here — enrollment flow is DEFERRED(M2).
            return FIDO2Backend(credential_id=b"")
    except ImportError:
        pass
    return None
