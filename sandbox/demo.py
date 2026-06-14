"""
Babbleon M1 sandbox demo.

Self-contained: doesn't touch the user's vault or real ~/.config.
Spins up a temp directory, runs the full lifecycle, prints the result.

Usage:  python3 sandbox/demo.py
"""
import pathlib
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

from babbleon.enforcement import View
from babbleon.session import DEFAULT_TRACKED, Session
from sandbox import attacker_sim


def _populate_fake_root(root: pathlib.Path) -> None:
    bin_dir = root / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    for name in DEFAULT_TRACKED:
        p = bin_dir / name
        p.write_text(f"#!/bin/sh\necho '{name} stub'\n")
        p.chmod(0o755)


def main() -> int:
    print("=== BABBLEON M1 SANDBOX DEMO ===\n")
    with tempfile.TemporaryDirectory(prefix="babbleon-demo-") as tmp:
        root = pathlib.Path(tmp)
        bin_dir = root / "bin"
        vault_file = root / "vault.age"
        _populate_fake_root(root)
        password = "demo-passphrase"

        # init
        print("[1] Initializing vault (Argon2id + age, ~1s)...")
        s = Session.initialize(password, vault_file=vault_file)
        print(f"    vault at {vault_file}\n")

        # show views
        trusted = View.trusted(s.tracked, bin_dir)
        untrusted = View.untrusted(s.mapping, bin_dir)

        print("[2] Trusted view (humans see real names):")
        for n in trusted.names()[:5]:
            print(f"    {n}")
        print(f"    ... ({len(trusted.names())} total)\n")

        print("[3] Untrusted view (payloads see scrambled compounds):")
        for n in untrusted.names()[:5]:
            real = s.mapping.reveal(n)
            print(f"    {n}  (was: {real})")
        print(f"    ... ({len(untrusted.names())} total)\n")

        # attacker against untrusted view
        print("[4] Running attacker simulation against UNTRUSTED view...")
        report = attacker_sim.run(
            visible_names=set(untrusted.names()),
            honey_names=s.payload.honey_names,
            env={},
            sandbox_creds_root=root,  # no creds in this sandbox
        )
        attacker_sim.print_report(report)

        # rotation
        print("[5] Rotating mapping (epoch 0 -> 1)...")
        sample = s.tracked[0]
        old = s.mapping.scramble(sample)
        s.rotate(password, vault_file=vault_file)
        new = s.mapping.scramble(sample)
        print(f"    {sample}: {old}")
        print(f"        ->  {new}\n")

        # attacker against rotated view
        untrusted2 = View.untrusted(s.mapping, bin_dir)
        print("[6] Attacker re-runs against rotated view (old probes are stale):")
        report2 = attacker_sim.run(
            visible_names=set(untrusted2.names()),
            honey_names=s.payload.honey_names,
            env={},
            sandbox_creds_root=root,
        )
        attacker_sim.print_report(report2)

        # honey-tripwire demo
        print("[7] Attacker probes a HONEY name from previous epoch...")
        # use one of the prior honey names against current view: it's not there,
        # but a probe could equally accidentally hit a current honey name.
        # demo: inject one current honey into "visible" set and re-run.
        honey_visible = set(untrusted2.names()) | {s.payload.honey_names[0]}
        report3 = attacker_sim.run(
            visible_names=honey_visible,
            honey_names=s.payload.honey_names,
            env={},
            sandbox_creds_root=root,
        )
        attacker_sim.print_report(report3)

    print("=== DEMO COMPLETE ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
