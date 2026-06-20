# Difficulty: 4 / 5
# Hint: sort by start; walk the sorted list; if the current interval
#       overlaps the last output interval, extend that one's end;
#       otherwise append the current as a fresh output entry.

def merge(intervals):
    if not intervals:
        return []
    sorted_intervals = sorted(intervals, key=lambda iv: iv[0])
    merged = [list(sorted_intervals[0])]
    for start, end in sorted_intervals[1:]:
        # {{INSERT}}
    return [tuple(iv) for iv in merged]


if __name__ == "__main__":
    assert merge([(1, 3), (2, 6), (8, 10), (15, 18)]) == [
        (1, 6), (8, 10), (15, 18)
    ]
    assert merge([(1, 4), (4, 5)]) == [(1, 5)]
    assert merge([]) == []
    assert merge([(1, 2)]) == [(1, 2)]
    assert merge([(5, 10), (1, 3)]) == [(1, 3), (5, 10)]
    print("ok")
