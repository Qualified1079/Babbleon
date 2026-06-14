"""Banner-spoofing wrapper: generation + null-output behavior."""
import pathlib
import subprocess

from babbleon.enforcement.wrapper import write_all, write_wrapper


def test_wrapper_generation(tmp_path: pathlib.Path):
    real_bin = tmp_path / "curl"
    real_bin.write_text("#!/bin/sh\necho real-curl-output\n")
    real_bin.chmod(0o755)

    out_dir = tmp_path / "scrambled"
    wp = write_wrapper("xxxyyyzzz", real_bin, out_dir, host_secret=b"k" * 32)
    assert wp.exists()
    assert wp.stat().st_mode & 0o111  # executable


def test_wrapper_null_on_help(tmp_path: pathlib.Path):
    real_bin = tmp_path / "curl"
    real_bin.write_text("#!/bin/sh\necho 'curl 8.0.0 — banner that would leak identity'\n")
    real_bin.chmod(0o755)

    wp = write_wrapper("abcd1234", real_bin, tmp_path / "out", host_secret=b"s" * 32)
    # --help should return empty
    r = subprocess.run([str(wp), "--help"], capture_output=True, text=True)
    assert r.returncode == 0
    assert r.stdout == ""
    # bare invocation should pass through to real binary
    r2 = subprocess.run([str(wp)], capture_output=True, text=True)
    assert "banner that would leak identity" in r2.stdout


def test_per_host_padding_differs(tmp_path: pathlib.Path):
    real_bin = tmp_path / "curl"
    real_bin.write_text("#!/bin/sh\n")
    real_bin.chmod(0o755)

    a = write_wrapper("name", real_bin, tmp_path / "a", host_secret=b"a" * 32)
    b = write_wrapper("name", real_bin, tmp_path / "b", host_secret=b"b" * 32)
    # padding makes the file contents differ even for identical inputs
    assert a.read_text() != b.read_text()


def test_write_all_skips_missing(tmp_path: pathlib.Path):
    real_root = tmp_path / "bin"
    real_root.mkdir()
    (real_root / "curl").write_text("#!/bin/sh\n")
    (real_root / "curl").chmod(0o755)
    # 'ssh' intentionally absent

    mapping_iter = [("curl", "scram-curl"), ("ssh", "scram-ssh")]
    result = write_all(mapping_iter, real_root, tmp_path / "out", b"k" * 32)
    assert "scram-curl" in result
    assert "scram-ssh" not in result
