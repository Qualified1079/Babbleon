# Difficulty: 2 / 5
# Hint: maintain a running max as you walk the list; at each position,
#       append max(current_max, x) to the output.

def running_max(values):
    current_max = float("-inf")
    out = []
    for x in values:
        # {{INSERT}}
        out.append(current_max)
    return out


if __name__ == "__main__":
    assert running_max([3, 1, 4, 1, 5, 9, 2, 6, 5, 3, 5]) == [
        3, 3, 4, 4, 5, 9, 9, 9, 9, 9, 9
    ]
    assert running_max([]) == []
    assert running_max([7]) == [7]
    print("ok")
