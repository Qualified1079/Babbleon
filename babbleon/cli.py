"""babbleon CLI: plant, list, verify, and clean up decoy/honeytoken files.

Usage:
    babbleon --path <repo> seed [pack ...]
    babbleon --path <repo> list [-v]
    babbleon --path <repo> verify <string>
    babbleon --path <repo> clean
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import decoys
from .registry import Registry


def cmd_seed(args):
    root = Path(args.path).resolve()
    registry = Registry(root)
    packs = decoys.ALL_PACKS
    if args.pack:
        packs = [p for p in decoys.ALL_PACKS if p.name in args.pack]
        if not packs:
            print(f"no matching packs for {args.pack!r}", file=sys.stderr)
            return 1
    for pack_cls in packs:
        pack = pack_cls()
        rel_path, tokens = decoys.write_pack(root, pack)
        registry.add(rel_path, pack.name, tokens)
        print(f"planted {pack.name} -> {rel_path} ({len(tokens)} token(s))")
    registry.save()
    print(f"registry: {registry.file} (gitignored -- do not commit)")
    return 0


def cmd_list(args):
    root = Path(args.path).resolve()
    registry = Registry(root)
    if not registry.entries:
        print("no decoys planted yet")
        return 0
    for entry in registry.entries:
        print(f"{entry['path']}  [{entry['pack']}]  {len(entry['tokens'])} token(s)")
        if args.verbose:
            for t in entry["tokens"]:
                print(f"    {t['kind']}: {t['value']}")
    return 0


def cmd_verify(args):
    root = Path(args.path).resolve()
    registry = Registry(root)
    hits = registry.find_by_value_substring(args.needle)
    if not hits:
        print("no match: this string was not planted by babbleon in this repo")
        return 1
    for entry, token in hits:
        print(f"MATCH: {token['kind']} from {entry['path']} (planted {entry['created_at']})")
    return 0


def cmd_clean(args):
    root = Path(args.path).resolve()
    registry = Registry(root)
    removed = 0
    for entry in registry.entries:
        p = root / entry["path"]
        if p.exists():
            p.unlink()
            removed += 1
    registry.entries = []
    registry.save()
    print(f"removed {removed} decoy file(s); registry cleared")
    return 0


def build_parser():
    parser = argparse.ArgumentParser(prog="babbleon")
    parser.add_argument("--path", default=".", help="target repository root")
    sub = parser.add_subparsers(dest="command", required=True)

    p_seed = sub.add_parser("seed", help="plant decoy files with honeytokens")
    p_seed.add_argument("pack", nargs="*", help="specific pack name(s); default all")
    p_seed.set_defaults(func=cmd_seed)

    p_list = sub.add_parser("list", help="list planted decoys")
    p_list.add_argument("-v", "--verbose", action="store_true")
    p_list.set_defaults(func=cmd_list)

    p_verify = sub.add_parser("verify", help="check if a string matches a planted honeytoken")
    p_verify.add_argument("needle")
    p_verify.set_defaults(func=cmd_verify)

    p_clean = sub.add_parser("clean", help="remove all planted decoys and clear the registry")
    p_clean.set_defaults(func=cmd_clean)

    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
