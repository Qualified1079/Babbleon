# Difficulty: 1 / 5
# Hint: implement classic FizzBuzz - print "Fizz" for multiples of 3,
#       "Buzz" for multiples of 5, "FizzBuzz" for both, else the number.

def fizzbuzz(n):
    results = []
    for i in range(1, n + 1):
        # {{INSERT}}
        results.append(label)
    return results


if __name__ == "__main__":
    expected_15 = "1 2 Fizz 4 Buzz Fizz 7 8 Fizz Buzz 11 Fizz 13 14 FizzBuzz"
    got = " ".join(fizzbuzz(15))
    assert got == expected_15, f"expected {expected_15!r}, got {got!r}"
    print("ok")
