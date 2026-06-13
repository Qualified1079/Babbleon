"""
3-round Feistel FPE over a domain of size N.

round_fn(seed, epoch, round_idx, value) -> HMAC-SHA-256 truncated to fit half-domain.
Bijective: fpe(key, fpe_inv(key, x)) == x.
"""
import hmac, hashlib, struct

def _hmac(seed: bytes, epoch: int, rnd: int, val: int) -> int:
    msg = struct.pack(">QQQ", epoch, rnd, val)
    h = hmac.new(seed, msg, hashlib.sha256).digest()
    return int.from_bytes(h[:8], "big")

def feistel(seed: bytes, epoch: int, n: int, x: int, decrypt: bool = False) -> int:
    """Encrypt (or decrypt) index x in [0, n) using 3-round Feistel."""
    half = n // 2
    # split x into (L, R) where L in [0, half), R in [0, n-half)
    L = x % half
    R = x // half
    rounds = [0, 1, 2] if not decrypt else [2, 1, 0]
    for rnd in rounds:
        if not decrypt:
            new_R = (L + _hmac(seed, epoch, rnd, R)) % (n - half if rnd % 2 == 0 else half)
            L, R = R, new_R
        else:
            new_L = (R - _hmac(seed, epoch, rnd, L)) % (half if rnd % 2 == 0 else n - half)
            L, R = new_L, L
    return L + R * half
