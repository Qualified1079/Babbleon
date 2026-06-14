"""
Bijective permutation of [0, N) keyed by (host_secret, epoch).

Implementation: seeded Fisher-Yates shuffle. The RNG is HMAC-DRBG-style:
HMAC-SHA-256(seed || epoch, counter) gives 32 bytes per call.

Permutation tables are cached per (seed, epoch, n) to amortize construction.

Properties:
- Bijective: encrypt is a permutation; decrypt is its inverse.
- Epoch independence: changing epoch reshuffles entirely.
- Deterministic: same (seed, epoch, n) always produces same permutation.

This replaces an earlier Feistel implementation that had correctness
issues on non-power-of-2 domains. A permutation table is O(N) memory,
which is fine for N <= a few million.
"""
import functools
import hashlib
import hmac
import struct


def _drbg_stream(seed: bytes, epoch: int, length: int) -> bytes:
    """Generate `length` deterministic bytes from (seed, epoch)."""
    out = bytearray()
    counter = 0
    base = seed + struct.pack(">Q", epoch)
    while len(out) < length:
        out.extend(hmac.new(base, struct.pack(">Q", counter), hashlib.sha256).digest())
        counter += 1
    return bytes(out[:length])


@functools.lru_cache(maxsize=16)
def _permutation(seed: bytes, epoch: int, n: int) -> tuple[tuple[int, ...], tuple[int, ...]]:
    """Build (perm, inverse) for domain [0, n). Cached."""
    if n <= 0:
        raise ValueError(f"n must be positive, got {n}")
    # need up to n random draws; 8 bytes per draw is plenty
    rand_bytes = _drbg_stream(seed, epoch, n * 8)
    perm = list(range(n))
    for i in range(n - 1, 0, -1):
        # uniform j in [0, i] from 8 bytes of randomness, modulo bias
        # negligible for n << 2^64
        r = int.from_bytes(rand_bytes[i * 8:(i + 1) * 8], "big")
        j = r % (i + 1)
        perm[i], perm[j] = perm[j], perm[i]
    inverse = [0] * n
    for idx, val in enumerate(perm):
        inverse[val] = idx
    return tuple(perm), tuple(inverse)


def encrypt(seed: bytes, epoch: int, n: int, x: int) -> int:
    if not (0 <= x < n):
        raise ValueError(f"x={x} out of range [0, {n})")
    perm, _ = _permutation(seed, epoch, n)
    return perm[x]


def decrypt(seed: bytes, epoch: int, n: int, y: int) -> int:
    if not (0 <= y < n):
        raise ValueError(f"y={y} out of range [0, {n})")
    _, inverse = _permutation(seed, epoch, n)
    return inverse[y]
