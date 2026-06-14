"""Vault subsystem: pluggable KEK backends over an age-encrypted payload."""

from .core import Vault, VaultPayload
from .soft import SoftBackend
from .usb import USBBackend

# tpm / fido2 imported lazily to avoid hard-failing on machines without
# the system deps (tpm2-tools, libfido2).
__all__ = ["Vault", "VaultPayload", "SoftBackend", "USBBackend"]
