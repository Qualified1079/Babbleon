# Difficulty: 3 / 5
# Hint: stack-based check; push opens, pop and match on closes,
#       reject on mismatch or empty pop.

def is_balanced(s):
    pairs = {")": "(", "]": "[", "}": "{"}
    opens = set(pairs.values())
    stack = []
    for ch in s:
        if ch in opens:
            stack.append(ch)
        elif ch in pairs:
            # {{INSERT}}
        # other chars are ignored
    return len(stack) == 0


if __name__ == "__main__":
    assert is_balanced("()") is True
    assert is_balanced("()[]{}") is True
    assert is_balanced("(]") is False
    assert is_balanced("([)]") is False
    assert is_balanced("{[]}") is True
    assert is_balanced("a(b)c[d{e}f]g") is True
    assert is_balanced(")(") is False
    print("ok")
