"""
Download and clean the dwyl/english-words wordlist.
Writes words.txt: one lowercase a-z word per line, ~370k entries.
"""
import urllib.request, pathlib, re, sys

URL = "https://raw.githubusercontent.com/dwyl/english-words/master/words_alpha.txt"
OUT = pathlib.Path(__file__).parent / "words.txt"

def fetch():
    print("fetching wordlist...", file=sys.stderr)
    with urllib.request.urlopen(URL, timeout=30) as r:
        raw = r.read().decode()
    words = [w.strip().lower() for w in raw.splitlines()]
    words = [w for w in words if re.fullmatch(r'[a-z]+', w) and len(w) >= 3]
    words = sorted(set(words))
    OUT.write_text("\n".join(words) + "\n")
    print(f"wrote {len(words)} words to {OUT}", file=sys.stderr)

if __name__ == "__main__":
    fetch()
