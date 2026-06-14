"""Vault seal/unseal + backend swap + wrong-passphrase rejection."""
import pytest

from babbleon.errors import WrongPassphrase
from babbleon.vault import SoftBackend, Vault, VaultPayload


def test_seal_unseal_roundtrip():
    v = Vault(SoftBackend())
    payload = VaultPayload.new(epoch=3, honey_names=["foo", "bar"])
    sealed = v.seal(payload, "correct horse battery staple")
    out = v.unseal(sealed, "correct horse battery staple")
    assert out.epoch == 3
    assert out.host_secret_hex == payload.host_secret_hex
    assert out.honey_names == ["foo", "bar"]


def test_wrong_passphrase_rejected():
    v = Vault(SoftBackend())
    payload = VaultPayload.new(epoch=0)
    sealed = v.seal(payload, "rightpass")
    with pytest.raises(WrongPassphrase):
        v.unseal(sealed, "wrongpass")


def test_payload_with_epoch_immutable():
    p = VaultPayload.new(epoch=0)
    p2 = p.with_epoch(5)
    assert p.epoch == 0 and p2.epoch == 5
    assert p.host_secret_hex == p2.host_secret_hex
