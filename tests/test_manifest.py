"""Manifest: default + TOML file loader."""
import pathlib

from babbleon.manifest import DEFAULT_TRACKED, Manifest


def test_default_manifest_nonempty():
    m = Manifest.default()
    assert len(m.tracked) > 0
    assert m.tracked == DEFAULT_TRACKED
    # ensure caller-mutation safety
    m.tracked.append("XXX")
    m2 = Manifest.default()
    assert "XXX" not in m2.tracked


def test_load_from_toml(tmp_path: pathlib.Path):
    p = tmp_path / "manifest.toml"
    p.write_text("""
[manifest]
version = 1
tracked = ["foo", "bar", "baz"]
""")
    m = Manifest.from_file(p)
    assert m.tracked == ["foo", "bar", "baz"]


def test_load_falls_back_to_default(tmp_path: pathlib.Path):
    missing = tmp_path / "nope.toml"
    m = Manifest.load(missing)
    assert m.tracked == DEFAULT_TRACKED
