"""
Command-line interface: `python -m babbleon <command>`.

Subcommands:
  init      create vault
  unlock    open vault, print epoch + sample mapping
  rotate    bump epoch
  trusted   print the trusted-view name list
  untrusted print the untrusted-view (scrambled) name list
  status    show vault state without unlocking
"""
import argparse
import getpass
import sys

from .errors import BabbleonError, VaultNotFound, WrongPassphrase
from .session import Session
from .storage import state_path, vault_path


def _read_password(prompt: str) -> str:
    if sys.stdin.isatty():
        return getpass.getpass(prompt)
    return sys.stdin.readline().rstrip("\n")


def cmd_init(args) -> int:
    pw = _read_password("choose passphrase: ")
    s = Session.initialize(pw)
    sample = next(iter(s.tracked), None)
    print(f"vault created at {vault_path()}")
    if sample:
        print(f"sample mapping: {sample} -> {s.mapping.scramble(sample)}")
    return 0


def cmd_unlock(args) -> int:
    pw = _read_password("passphrase: ")
    s = Session.unlock(pw)
    print(f"epoch: {s.payload.epoch}")
    print(f"tools tracked: {len(s.tracked)}")
    print(f"honey tripwires: {len(s.payload.honey_names)}")
    return 0


def cmd_rotate(args) -> int:
    pw = _read_password("passphrase: ")
    s = Session.unlock(pw)
    old = s.payload.epoch
    new = s.rotate(pw)
    print(f"rotated epoch {old} -> {new}")
    return 0


def cmd_trusted(args) -> int:
    pw = _read_password("passphrase: ")
    s = Session.unlock(pw)
    for name in sorted(s.tracked):
        print(name)
    return 0


def cmd_untrusted(args) -> int:
    pw = _read_password("passphrase: ")
    s = Session.unlock(pw)
    for name in sorted(s.tracked):
        print(f"{s.mapping.scramble(name)}  (was: {name})")
    return 0


def cmd_status(args) -> int:
    vp = vault_path()
    if not vp.exists():
        print("no vault present; run `babbleon init`")
        return 1
    print(f"vault: {vp} ({vp.stat().st_size} bytes)")
    sp = state_path()
    if sp.exists():
        print(f"state: {sp.read_text().strip()}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="babbleon")
    sub = parser.add_subparsers(dest="cmd", required=True)
    for name, fn in [
        ("init", cmd_init),
        ("unlock", cmd_unlock),
        ("rotate", cmd_rotate),
        ("trusted", cmd_trusted),
        ("untrusted", cmd_untrusted),
        ("status", cmd_status),
    ]:
        p = sub.add_parser(name)
        p.set_defaults(func=fn)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except WrongPassphrase:
        print("error: wrong passphrase", file=sys.stderr)
        return 2
    except VaultNotFound as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3
    except BabbleonError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 4


if __name__ == "__main__":
    sys.exit(main())
