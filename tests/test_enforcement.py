"""SimulatedDriver: view materialization without kernel calls."""
import pathlib

from babbleon.enforcement import SimulatedDriver, View
from babbleon.mapping import Mapper

TOOLS = ["curl", "ssh", "git"]


def _stub_root(tmp: pathlib.Path) -> pathlib.Path:
    root = tmp / "bin"
    root.mkdir()
    for t in TOOLS:
        (root / t).write_text("#!/bin/sh\n")
        (root / t).chmod(0o755)
    return root


def test_simulated_trusted(tmp_path: pathlib.Path):
    root = _stub_root(tmp_path)
    d = SimulatedDriver()
    r = d.present_trusted(root, TOOLS)
    assert r.tier == "trusted"
    assert set(r.visible.keys()) == set(TOOLS)


def test_simulated_untrusted(tmp_path: pathlib.Path):
    root = _stub_root(tmp_path)
    table = Mapper(b"s" * 32).build_table(TOOLS, 0)
    d = SimulatedDriver()
    r = d.present_untrusted(root, table)
    assert r.tier == "untrusted"
    for scrambled in r.visible:
        assert scrambled not in TOOLS  # nothing is canonical-named
        assert table.reveal(scrambled) in TOOLS


def test_view_resolve(tmp_path: pathlib.Path):
    root = _stub_root(tmp_path)
    view = View.trusted(TOOLS, root)
    assert view.resolve("curl") == root / "curl"
    assert view.resolve("nonexistent") is None
