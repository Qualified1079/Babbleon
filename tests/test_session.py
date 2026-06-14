"""Session lifecycle: init, unlock, rotate."""
import pathlib

from babbleon.session import Session


def test_init_then_unlock(tmp_path: pathlib.Path):
    vault = tmp_path / "vault.age"
    s1 = Session.initialize("pw", tracked=["curl", "ssh"], vault_file=vault)
    s2 = Session.unlock("pw", tracked=["curl", "ssh"], vault_file=vault)
    assert s1.mapping.scramble("curl") == s2.mapping.scramble("curl")
    assert s1.payload.epoch == s2.payload.epoch == 0


def test_rotate_bumps_epoch_and_remaps(tmp_path: pathlib.Path):
    vault = tmp_path / "vault.age"
    s = Session.initialize("pw", tracked=["curl"], vault_file=vault)
    old = s.mapping.scramble("curl")
    s.rotate("pw", vault_file=vault)
    new = s.mapping.scramble("curl")
    assert s.payload.epoch == 1
    assert old != new
    # vault on disk reflects new epoch
    s2 = Session.unlock("pw", tracked=["curl"], vault_file=vault)
    assert s2.payload.epoch == 1
