"""USB keyfile backend: enrollment, single-factor, 2FA, missing file."""
import pathlib

import pytest

from babbleon.errors import VaultError
from babbleon.vault import USBBackend, Vault, VaultPayload


def test_keyfile_only_roundtrip(tmp_path: pathlib.Path):
    kf = tmp_path / "key.bin"
    USBBackend.generate_keyfile(kf)
    backend = USBBackend(kf)
    v = Vault(backend)
    payload = VaultPayload.new(epoch=0)
    sealed = v.seal(payload, credential=None)
    out = v.unseal(sealed, credential=None)
    assert out.host_secret_hex == payload.host_secret_hex


def test_keyfile_plus_password_2fa(tmp_path: pathlib.Path):
    kf = tmp_path / "key.bin"
    USBBackend.generate_keyfile(kf)
    backend = USBBackend(kf)
    v = Vault(backend)
    payload = VaultPayload.new(epoch=7)
    sealed = v.seal(payload, credential="my-2fa-pw")
    out = v.unseal(sealed, credential="my-2fa-pw")
    assert out.epoch == 7


def test_missing_keyfile_raises(tmp_path: pathlib.Path):
    backend = USBBackend(tmp_path / "nonexistent")
    v = Vault(backend)
    with pytest.raises(VaultError):
        v.seal(VaultPayload.new(), credential=None)


def test_different_keyfiles_diverge(tmp_path: pathlib.Path):
    kf1, kf2 = tmp_path / "a.bin", tmp_path / "b.bin"
    USBBackend.generate_keyfile(kf1)
    USBBackend.generate_keyfile(kf2)
    v1 = Vault(USBBackend(kf1))
    v2 = Vault(USBBackend(kf2))
    payload = VaultPayload.new()
    sealed = v1.seal(payload, credential=None)
    from babbleon.errors import WrongPassphrase
    with pytest.raises(WrongPassphrase):
        v2.unseal(sealed, credential=None)
