"""
Soft-tier vault backend: Argon2id password -> age passphrase.

Security honest copy: raises cost of automated credential theft; not a
defense against persistent code execution with memory access.

Parameters (per PLAN.md §7):
  Argon2id, m=46 MiB, t=2, p=1 — tuned for laptops.
  Salt is fixed (randomization lives in host_secret, not here).
"""
from argon2.low_level import Type, hash_secret_raw

# REVIEW(manual): adjust m/t if targeting IoT or headless servers; 46MiB/t=2
# is sized for laptop RAM. Increasing t while lowering m keeps equivalent
# time-cost on constrained devices.
_ARGON2_PARAMS = dict(
    time_cost=2,
    memory_cost=46 * 1024,  # KiB
    parallelism=1,
    hash_len=32,
    type=Type.ID,
)
_SALT = b"babbleon-soft-v1"  # fixed; randomization lives in host_secret


class SoftBackend:
    """KEK backend: user passphrase stretched via Argon2id."""

    def derive_age_passphrase(self, password: str) -> str:
        raw = hash_secret_raw(secret=password.encode(), salt=_SALT, **_ARGON2_PARAMS)
        return raw.hex()
