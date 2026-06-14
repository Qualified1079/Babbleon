"""Download dwyl/english-words wordlist; clean to ~370k lowercase entries."""
import pathlib
import re
import sys
import urllib.request

URL = "https://raw.githubusercontent.com/dwyl/english-words/master/words_alpha.txt"
OUT = pathlib.Path(__file__).parent / "words.txt"


def fetch() -> int:
    sys.stderr.write("fetching wordlist...\n")
    with urllib.request.urlopen(URL, timeout=30) as r:
        raw = r.read().decode()
    words = sorted({
        w.strip().lower()
        for w in raw.splitlines()
        if re.fullmatch(r"[a-z]+", w.strip().lower()) and len(w.strip()) >= 3
    })
    OUT.write_text("\n".join(words) + "\n")
    sys.stderr.write(f"wrote {len(words)} words to {OUT}\n")
    return len(words)


if __name__ == "__main__":
    fetch()
