"""
Babbleon M1 sandbox demo.

Usage:
  python3 demo.py init           # create vault + populate sandbox/bin/
  python3 demo.py trusted        # show trusted view (real names)
  python3 demo.py untrusted      # show untrusted (scrambled) view
  python3 demo.py attacker       # run attacker sim against untrusted view
  python3 demo.py rotate         # rotate mapping (new epoch)
  python3 demo.py all            # run full demo sequence
"""
import getpass, json, os, pathlib, stat, sys
sys.path.insert(0, str(pathlib.Path(__file__).parent))

import vault as vlt
import mapping as mp
import views
import attacker_sim

SANDBOX_BIN = pathlib.Path(__file__).parent / "bin"
STATE_FILE = pathlib.Path(__file__).parent / "vault" / "state.json"
HONEY_N = 50


def _get_password(prompt: str = "passphrase: ") -> str:
    if sys.stdin.isatty():
        return getpass.getpass(prompt)
    return sys.stdin.readline().strip()


def _save_state(epoch: int):
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps({"epoch": epoch}))


def _load_state() -> int:
    if STATE_FILE.exists():
        return json.loads(STATE_FILE.read_text()).get("epoch", 0)
    return 0


def _populate_sandbox():
    """Create stub binaries in sandbox/bin/ for each tracked tool."""
    SANDBOX_BIN.mkdir(parents=True, exist_ok=True)
    for name in views.TRACKED:
        p = SANDBOX_BIN / name
        if not p.exists():
            p.write_text(f"#!/bin/sh\necho '{name} stub'\n")
            p.chmod(p.stat().st_mode | stat.S_IEXEC)
    print(f"sandbox/bin/ populated with {len(views.TRACKED)} stub binaries.")


def cmd_init():
    _populate_sandbox()
    password = _get_password("choose a passphrase: ")
    host_secret = os.urandom(32)
    epoch = 0

    mapping = mp.build_mapping(views.TRACKED, host_secret, epoch)
    honey = mp.build_honey_mapping(HONEY_N, host_secret, epoch)

    vlt.save(password, host_secret, epoch, honey)
    _save_state(epoch)

    print(f"\nVault created (epoch {epoch}).")
    print(f"Mapping sample: curl -> {mapping.get('curl', '?')}")
    print(f"Honey sample:   {honey[0]}")


def cmd_trusted():
    v = views.trusted_view()
    print("\n=== TRUSTED VIEW (what humans see) ===")
    for name, path in sorted(v.items()):
        print(f"  {name:<20} -> {path}")
    print(f"Total: {len(v)} tools")


def cmd_untrusted(payload: dict | None = None):
    if payload is None:
        password = _get_password()
        payload = vlt.load(password)
    host_secret = bytes.fromhex(payload["host_secret"])
    epoch = payload["epoch"]
    mapping = mp.build_mapping(views.TRACKED, host_secret, epoch)
    uv = views.untrusted_view(mapping)
    print("\n=== UNTRUSTED VIEW (what a payload sees) ===")
    for scrambled, path in sorted(uv.items()):
        real = next(k for k, v in mapping.items() if v == scrambled)
        print(f"  {scrambled:<55} (was: {real})")
    print(f"Total: {len(uv)} tools  |  epoch: {epoch}")


def cmd_attacker(payload: dict | None = None):
    if payload is None:
        password = _get_password()
        payload = vlt.load(password)
    host_secret = bytes.fromhex(payload["host_secret"])
    epoch = payload["epoch"]
    mapping = mp.build_mapping(views.TRACKED, host_secret, epoch)
    uv = views.untrusted_view(mapping)
    honey = payload.get("honey_names", [])

    print("\n[attacker has access to the UNTRUSTED view only]")
    attacker_sim.run(uv, honey)


def cmd_rotate():
    password = _get_password()
    payload = vlt.load(password)
    host_secret = bytes.fromhex(payload["host_secret"])
    old_epoch = payload["epoch"]
    new_epoch = old_epoch + 1

    honey = mp.build_honey_mapping(HONEY_N, host_secret, new_epoch)
    vlt.save(password, host_secret, new_epoch, honey)
    _save_state(new_epoch)

    old_map = mp.build_mapping(views.TRACKED, host_secret, old_epoch)
    new_map = mp.build_mapping(views.TRACKED, host_secret, new_epoch)
    print(f"\nRotated epoch {old_epoch} -> {new_epoch}")
    print(f"  curl: {old_map.get('curl')} -> {new_map.get('curl')}")


def cmd_all():
    print("=== BABBLEON M1 DEMO ===\n")
    _populate_sandbox()
    password = "demo-passphrase"
    host_secret = os.urandom(32)
    epoch = 0
    mapping = mp.build_mapping(views.TRACKED, host_secret, epoch)
    honey = mp.build_honey_mapping(HONEY_N, host_secret, epoch)
    vault_bytes = vlt.create(password, host_secret, epoch, honey)
    payload = vlt.unlock(password, vault_bytes)

    cmd_trusted()
    cmd_untrusted(payload)
    cmd_attacker(payload)

    # rotate and show attacker fails again
    new_epoch = 1
    new_mapping = mp.build_mapping(views.TRACKED, host_secret, new_epoch)
    new_honey = mp.build_honey_mapping(HONEY_N, host_secret, new_epoch)
    new_vault = vlt.create(password, host_secret, new_epoch, new_honey)
    new_payload = vlt.unlock(password, new_vault)

    print("--- After rotation (epoch 0 -> 1) ---")
    print(f"curl mapping changed: {mapping['curl']} -> {new_mapping['curl']}")
    print("[attacker re-runs with stale mapping from epoch 0 — all names now wrong]")
    # run attacker against epoch-1 view with epoch-0 honey (stale names)
    uv1 = views.untrusted_view(new_mapping)
    attacker_sim.run(uv1, honey, verbose=True)


COMMANDS = {
    "init": cmd_init,
    "trusted": cmd_trusted,
    "untrusted": cmd_untrusted,
    "attacker": cmd_attacker,
    "rotate": cmd_rotate,
    "all": cmd_all,
}

if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "all"
    if cmd not in COMMANDS:
        print(f"unknown command: {cmd}. choices: {', '.join(COMMANDS)}")
        sys.exit(1)
    COMMANDS[cmd]()
