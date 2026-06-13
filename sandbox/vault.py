"""
Vault: stores the host_secret (mapping seed) encrypted with Argon2id + age.

Format (vault.age): age-encrypted JSON payload:
  { "epoch": int, "host_secret": hex, "honey_names": [str] }

Soft tier only for M1: passphrase -> Argon2id -> age passphrase recipient.
"""
import json, os, pathlib, sys
import pyrage
import pyrage.passphrase
from argon2.low_level import Type, hash_secret_raw

VAULT_PATH = pathlib.Path(__file__).parent / "vault" / "vault.age"
PARAMS = dict(time_cost=2, memory_cost=46 * 1024, parallelism=1, hash_len=32, type=Type.ID)

def _derive_age_passphrase(password: str) -> str:
    """Argon2id-stretch the user password into the age passphrase."""
    salt = b"babbleon-v1-salt"  # fixed salt; randomization is in host_secret
    raw = hash_secret_raw(
        secret=password.encode(),
        salt=salt,
        **PARAMS,
    )
    return raw.hex()

def create(password: str, host_secret: bytes | None = None, epoch: int = 0,
           honey_names: list[str] | None = None) -> bytes:
    """Create and return encrypted vault bytes."""
    if host_secret is None:
        host_secret = os.urandom(32)
    payload = json.dumps({
        "epoch": epoch,
        "host_secret": host_secret.hex(),
        "honey_names": honey_names or [],
    }).encode()
    age_pass = _derive_age_passphrase(password)
    return pyrage.passphrase.encrypt(payload, age_pass)

def unlock(password: str, vault_bytes: bytes) -> dict:
    """Decrypt vault and return payload dict."""
    age_pass = _derive_age_passphrase(password)
    raw = pyrage.passphrase.decrypt(vault_bytes, age_pass)
    return json.loads(raw)

def save(password: str, host_secret: bytes, epoch: int = 0,
         honey_names: list[str] | None = None):
    VAULT_PATH.parent.mkdir(parents=True, exist_ok=True)
    data = create(password, host_secret, epoch, honey_names)
    VAULT_PATH.write_bytes(data)
    print(f"vault written to {VAULT_PATH}", file=sys.stderr)

def load(password: str) -> dict:
    data = VAULT_PATH.read_bytes()
    return unlock(password, data)
