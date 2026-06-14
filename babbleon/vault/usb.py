"""
USB-keyfile vault backend: key material on removable media, optional password 2FA.

The keyfile is 32 random bytes. With a password, the KEK is
HKDF(keyfile || Argon2id(password), "babbleon-usb-v1").
Without a password, the KEK is derived from keyfile alone (single-factor).

The keyfile path is stored in the vault header comment (unencrypted).
REVIEW(manual): keyfile path disclosure is metadata leak; evaluate whether
to store it encrypted in a separate header block.
"""
import hashlib
import os
import pathlib

from argon2.low_level import Type, hash_secret_raw

from ..errors import VaultError

_ARGON2_PARAMS = dict(time_cost=2, memory_cost=46 * 1024, parallelism=1, hash_len=32, type=Type.ID)
_SALT = b"babbleon-usb-v1"
_KEYFILE_SIZE = 32


class USBBackend:
    """KEK backend: keyfile on removable media, optional passphrase 2FA."""

    def __init__(self, keyfile_path: pathlib.Path | str) -> None:
        self.keyfile_path = pathlib.Path(keyfile_path)

    @classmethod
    def generate_keyfile(cls, path: pathlib.Path | str) -> None:
        """Write a new random keyfile. Call once during enrollment."""
        p = pathlib.Path(path)
        p.write_bytes(os.urandom(_KEYFILE_SIZE))
        p.chmod(0o600)

    def derive_age_passphrase(self, password: str | None = None) -> str:
        if not self.keyfile_path.exists():
            raise VaultError(f"keyfile not found: {self.keyfile_path}")
        keyfile_bytes = self.keyfile_path.read_bytes()
        if len(keyfile_bytes) < _KEYFILE_SIZE:
            raise VaultError("keyfile too short; may be corrupt")

        if password:
            pw_raw = hash_secret_raw(secret=password.encode(), salt=_SALT, **_ARGON2_PARAMS)
            material = keyfile_bytes + pw_raw
        else:
            material = keyfile_bytes

        kek = hashlib.sha256(material + b"babbleon-usb-kek-v1").hexdigest()
        return kek
