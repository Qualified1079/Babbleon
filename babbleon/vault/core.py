"""
Vault core: serialization, encryption, and backend protocol.

A Vault wraps VaultPayload (epoch + host_secret + honey_names) in
age encryption. The KEK (key-encryption key) is provided by a backend.

Backend protocol: any object with:
  .derive_age_passphrase(password_or_None) -> str
"""
import json
import os
from dataclasses import dataclass, asdict

import pyrage
import pyrage.passphrase

from ..errors import VaultError, WrongPassphrase


@dataclass
class VaultPayload:
    """The plaintext contents of the vault."""
    epoch: int
    host_secret_hex: str
    honey_names: list[str]

    @classmethod
    def new(cls, epoch: int = 0, honey_names: list[str] | None = None) -> "VaultPayload":
        return cls(
            epoch=epoch,
            host_secret_hex=os.urandom(32).hex(),
            honey_names=honey_names or [],
        )

    @property
    def host_secret(self) -> bytes:
        return bytes.fromhex(self.host_secret_hex)

    def with_epoch(self, epoch: int) -> "VaultPayload":
        return VaultPayload(epoch=epoch, host_secret_hex=self.host_secret_hex, honey_names=self.honey_names)

    def with_honey(self, honey_names: list[str]) -> "VaultPayload":
        return VaultPayload(epoch=self.epoch, host_secret_hex=self.host_secret_hex, honey_names=honey_names)


class Vault:
    """Encrypts/decrypts VaultPayload using a backend-supplied passphrase."""

    def __init__(self, backend) -> None:
        self._backend = backend

    def seal(self, payload: VaultPayload, credential=None) -> bytes:
        """Encrypt payload; returns age-encrypted bytes."""
        age_pass = self._backend.derive_age_passphrase(credential)
        plaintext = json.dumps(asdict(payload)).encode()
        return pyrage.passphrase.encrypt(plaintext, age_pass)

    def unseal(self, data: bytes, credential=None) -> VaultPayload:
        """Decrypt vault bytes; raises WrongPassphrase on failure."""
        age_pass = self._backend.derive_age_passphrase(credential)
        try:
            plaintext = pyrage.passphrase.decrypt(data, age_pass)
        except Exception as exc:
            raise WrongPassphrase("vault decryption failed") from exc
        try:
            d = json.loads(plaintext)
            return VaultPayload(**d)
        except Exception as exc:
            raise VaultError("vault payload malformed") from exc
