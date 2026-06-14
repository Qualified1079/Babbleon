"""
On-disk paths for vault, state, config.

Honors XDG_CONFIG_HOME / XDG_DATA_HOME. M1 uses ~/.config/babbleon and
~/.local/share/babbleon by default.
"""
import os
import pathlib


def config_dir() -> pathlib.Path:
    base = os.environ.get("XDG_CONFIG_HOME") or "~/.config"
    return pathlib.Path(base).expanduser() / "babbleon"


def data_dir() -> pathlib.Path:
    base = os.environ.get("XDG_DATA_HOME") or "~/.local/share"
    return pathlib.Path(base).expanduser() / "babbleon"


def vault_path() -> pathlib.Path:
    return config_dir() / "vault.age"


def state_path() -> pathlib.Path:
    return config_dir() / "state.json"


def ensure_dirs() -> None:
    config_dir().mkdir(parents=True, exist_ok=True)
    data_dir().mkdir(parents=True, exist_ok=True)
    try:
        config_dir().chmod(0o700)
    except PermissionError:
        pass
