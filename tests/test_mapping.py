"""Mapping table properties: uniqueness, rotation, honey separation."""
from babbleon.mapping import Mapper

TOOLS = ["curl", "ssh", "git", "aws", "docker", "kubectl"]


def test_no_collisions():
    table = Mapper(b"s" * 32).build_table(TOOLS, epoch=0)
    scrambled = list(table.real_to_scrambled.values())
    assert len(set(scrambled)) == len(scrambled)


def test_roundtrip():
    table = Mapper(b"s" * 32).build_table(TOOLS, epoch=0)
    for real in TOOLS:
        s = table.scramble(real)
        assert s is not None
        assert table.reveal(s) == real


def test_rotation_changes_all_names():
    m = Mapper(b"s" * 32)
    t0 = m.build_table(TOOLS, 0)
    t1 = m.build_table(TOOLS, 1)
    for tool in TOOLS:
        assert t0.scramble(tool) != t1.scramble(tool)


def test_honey_disjoint_from_real():
    table = Mapper(b"s" * 32).build_table(TOOLS, 0)
    reals = set(table.real_to_scrambled.values())
    honey = set(table.honey_names)
    assert reals.isdisjoint(honey)


def test_different_secrets_diverge():
    t1 = Mapper(b"a" * 32).build_table(TOOLS, 0)
    t2 = Mapper(b"b" * 32).build_table(TOOLS, 0)
    for tool in TOOLS:
        assert t1.scramble(tool) != t2.scramble(tool)
