"""
KEKBackend protocol: the only contract the public Vault class depends on.

Enterprise backends (HSM, HashiCorp Vault, escrow-server) implement this
and register via the babbleon.vault_backends entry_point group. They never
need to import anything from the public vault subpackage — only this module.
"""

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class KEKBackend(Protocol):
    """
    Key-encryption key provider.

    `credential` is tier-specific:
      SoftBackend     -> str (passphrase)
      USBBackend      -> str (passphrase) or None
      TPMBackend      -> None (TPM handles auth internally)
      FIDO2Backend    -> None (token handles auth; tap required)
      Enterprise HSM  -> dict with connection params
    """
    def derive_age_passphrase(self, credential: Any) -> str: ...
