"""
Per-host mapping construction.

Mapper builds a bijective real_name -> scrambled_name table using
Feistel FPE over the wordlist. The only secret is host_secret.

Compound names: COMPOUND_N words, all-lowercase, no separators.
Honey names: bait entries that look real but map to nothing.
"""
import hashlib
import pathlib
from dataclasses import dataclass

from .fpe import encrypt as fpe_encrypt

WORDLIST_PATH = pathlib.Path(__file__).parent / "wordlist" / "words.txt"
COMPOUND_N = 4
HONEY_COUNT = 50


@dataclass(frozen=True)
class MappingTable:
    """Immutable scramble mapping snapshot for one epoch."""

    epoch: int
    real_to_scrambled: dict[str, str]
    scrambled_to_real: dict[str, str]
    honey_names: list[str]

    def scramble(self, real_name: str) -> str | None:
        return self.real_to_scrambled.get(real_name)

    def reveal(self, scrambled_name: str) -> str | None:
        return self.scrambled_to_real.get(scrambled_name)

    def is_honey(self, name: str) -> bool:
        return name in self.honey_names


class Mapper:
    """Stateless mapping builder. Call build_table() per epoch."""

    def __init__(self, host_secret: bytes) -> None:
        self._host_secret = host_secret
        self._words: list[str] | None = None

    def _words_list(self) -> list[str]:
        if self._words is None:
            self._words = WORDLIST_PATH.read_text().splitlines()
        return self._words

    def _seed(self, purpose: str) -> bytes:
        return hashlib.sha256(self._host_secret + purpose.encode()).digest()

    def _compound(self, seed: bytes, epoch: int, slot_base: int) -> str:
        words = self._words_list()
        n = len(words)
        parts = [words[fpe_encrypt(seed, epoch, n, (slot_base + i) % n)] for i in range(COMPOUND_N)]
        return "".join(parts)

    def build_table(self, real_names: list[str], epoch: int) -> MappingTable:
        seed = self._seed("babbleon-mapping-v1")
        honey_seed = self._seed("babbleon-honey-v1")

        r2s: dict[str, str] = {}
        s2r: dict[str, str] = {}
        for i, name in enumerate(real_names):
            s = self._compound(seed, epoch, i * COMPOUND_N)
            r2s[name] = s
            s2r[s] = name

        honey = [self._compound(honey_seed, epoch, i * COMPOUND_N) for i in range(HONEY_COUNT)]

        return MappingTable(epoch=epoch, real_to_scrambled=r2s, scrambled_to_real=s2r, honey_names=honey)
