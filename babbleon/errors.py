"""Package-wide exception hierarchy. Import from here, not from submodules."""


class BabbleonError(Exception):
    """Base for all Babbleon errors."""


class VaultError(BabbleonError):
    """Vault open/decrypt/integrity failure."""


class WrongPassphrase(VaultError):
    """Passphrase or key did not decrypt the vault."""


class VaultNotFound(VaultError):
    """No vault file found at the expected path."""


class HardwareUnavailable(VaultError):
    """TPM / FIDO2 token absent or unresponsive."""


class MappingError(BabbleonError):
    """Mapping construction or lookup failure."""


class EnforcementError(BabbleonError):
    """Namespace setup or view enforcement failure."""
