"""FPE properties: bijectivity, epoch independence, basic distribution."""
import pytest

from babbleon.mapping.fpe import encrypt, decrypt


def test_bijective_small():
    seed = b"x" * 32
    n = 100
    outputs = [encrypt(seed, 0, n, i) for i in range(n)]
    assert sorted(outputs) == list(range(n)), "FPE must be a permutation"


def test_decrypt_roundtrip():
    seed = b"k" * 32
    n = 1000
    for x in range(0, n, 17):
        y = encrypt(seed, 0, n, x)
        assert decrypt(seed, 0, n, y) == x


def test_epoch_changes_mapping():
    seed = b"k" * 32
    n = 1000
    e0 = [encrypt(seed, 0, n, i) for i in range(n)]
    e1 = [encrypt(seed, 1, n, i) for i in range(n)]
    diff = sum(1 for a, b in zip(e0, e1) if a != b)
    assert diff > n * 0.9, "rotation must move >90% of indices"


def test_out_of_range_raises():
    with pytest.raises(ValueError):
        encrypt(b"k" * 32, 0, 100, 100)
    with pytest.raises(ValueError):
        encrypt(b"k" * 32, 0, 100, -1)
