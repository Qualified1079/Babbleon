"""
Build and query the per-host scramble mapping.

mapping[real_name] -> scrambled_name  (for untrusted view)
"""
import hashlib, pathlib, struct
from fpe import feistel

WORDLIST = pathlib.Path(__file__).parent / "wordlist" / "words.txt"
COMPOUND_N = 4  # words per scrambled name

def _load_words() -> list[str]:
    return WORDLIST.read_text().splitlines()

def _derive_seed(host_secret: bytes, purpose: str) -> bytes:
    return hashlib.sha256(host_secret + purpose.encode()).digest()

def build_mapping(real_names: list[str], host_secret: bytes, epoch: int = 0) -> dict[str, str]:
    words = _load_words()
    W = len(words)
    seed = _derive_seed(host_secret, "babbleon-fpe-v1")

    mapping: dict[str, str] = {}
    for i, name in enumerate(real_names):
        # map index i -> COMPOUND_N word indices via Feistel, each in [0, W)
        parts = []
        for slot in range(COMPOUND_N):
            idx_in = (i * COMPOUND_N + slot) % W
            idx_out = feistel(seed, epoch, W, idx_in) % W
            parts.append(words[idx_out])
        mapping[name] = "".join(parts)
    return mapping

def build_honey_mapping(n: int, host_secret: bytes, epoch: int = 0) -> list[str]:
    """Return n bait names that look like scrambled names but map to nothing real."""
    words = _load_words()
    W = len(words)
    seed = _derive_seed(host_secret, "babbleon-honey-v1")
    result = []
    for i in range(n):
        parts = []
        for slot in range(COMPOUND_N):
            idx_out = feistel(seed, epoch, W, (i * COMPOUND_N + slot) % W) % W
            parts.append(words[idx_out])
        result.append("".join(parts))
    return result
