# Difficulty: 3 / 5
# Hint: group words by sorted-letter signature.
#       The dict maps signature -> list[word].

def anagram_groups(words):
    by_signature = {}
    for w in words:
        # {{INSERT}}
        by_signature.setdefault(signature, []).append(w)
    return sorted(by_signature.values(), key=lambda g: g[0])


if __name__ == "__main__":
    got = anagram_groups(["eat", "tea", "tan", "ate", "nat", "bat"])
    expected = [["bat"], ["eat", "tea", "ate"], ["tan", "nat"]]
    assert sorted(map(sorted, got)) == sorted(map(sorted, expected))
    print("ok")
