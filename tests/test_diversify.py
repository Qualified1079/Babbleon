import textwrap
import unittest

from babbleon.diversify import diversify_source


def run_and_collect(source: str, calls: list[str]) -> list:
    namespace: dict = {}
    exec(compile(source, "<test>", "exec"), namespace)
    return [eval(call, namespace) for call in calls]


class DiversifyBehaviorPreservationTests(unittest.TestCase):
    def assert_behavior_preserved(self, source: str, calls: list[str], seed: str = "seed-a"):
        source = textwrap.dedent(source)
        original = run_and_collect(source, calls)
        diversified = diversify_source(source, seed)
        result = run_and_collect(diversified, calls)
        self.assertEqual(original, result)
        return diversified

    def test_simple_locals_renamed_and_behavior_preserved(self):
        source = """
            def compute(n):
                total = 0
                step = 2
                for i in range(n):
                    total += i * step
                return total
        """
        diversified = self.assert_behavior_preserved(source, ["compute(10)"])
        self.assertNotIn("total", diversified)
        self.assertNotIn("step", diversified)

    def test_parameters_are_not_renamed(self):
        source = """
            def greet(name, greeting="hi"):
                return f"{greeting}, {name}!"
        """
        diversified = self.assert_behavior_preserved(
            source, ["greet('world')", "greet('world', greeting='yo')"]
        )
        self.assertIn("def greet(name, greeting='hi')", diversified)

    def test_tuple_unpacking_renamed_consistently(self):
        source = """
            def swap_sum(pair):
                a, b = pair
                a, b = b, a
                return a + b, a - b
        """
        diversified = self.assert_behavior_preserved(source, ["swap_sum((3, 5))"])
        self.assertNotIn(" a ", diversified)
        self.assertNotIn(" b ", diversified)

    def test_closure_variable_is_left_untouched(self):
        source = """
            def make_counter():
                count = 0
                def bump():
                    nonlocal count
                    count += 1
                    return count
                return bump
        """
        diversified = self.assert_behavior_preserved(
            source,
            ["(lambda f: [f(), f(), f()])(make_counter())"],
        )
        self.assertIn("count", diversified)

    def test_global_declared_name_is_left_untouched(self):
        source = """
            counter = 0

            def bump_global():
                global counter
                counter += 1
                return counter
        """
        diversified = self.assert_behavior_preserved(
            source, ["bump_global()", "bump_global()", "counter"]
        )
        self.assertIn("global counter", diversified)

    def test_exception_alias_renamed(self):
        source = """
            def safe_div(a, b):
                try:
                    return a / b
                except ZeroDivisionError as err:
                    return str(err)
        """
        diversified = self.assert_behavior_preserved(
            source, ["safe_div(4, 2)", "safe_div(4, 0)"]
        )
        self.assertNotIn("as err", diversified)

    def test_walrus_in_comprehension_leaks_to_function_scope(self):
        source = """
            def last_even(values):
                result = None
                evens = [result := v for v in values if v % 2 == 0]
                return result, evens
        """
        diversified = self.assert_behavior_preserved(source, ["last_even([1, 2, 3, 4, 5])"])
        self.assertNotIn("result", diversified)

    def test_method_locals_renamed_self_preserved(self):
        source = """
            class Accumulator:
                def __init__(self):
                    self.total = 0

                def add(self, amount):
                    delta = amount * 2
                    self.total += delta
                    return self.total
        """
        diversified = self.assert_behavior_preserved(
            source,
            [
                "(lambda a: [a.add(1), a.add(2)])(Accumulator())",
            ],
        )
        self.assertIn("self.total", diversified)
        self.assertNotIn("delta", diversified)

    def test_class_and_function_names_are_stable(self):
        source = """
            def helper(x):
                y = x + 1
                return y

            class Widget:
                def size(self):
                    n = 3
                    return n
        """
        diversified = diversify_source(textwrap.dedent(source), "seed-a")
        self.assertIn("def helper(x):", diversified)
        self.assertIn("class Widget:", diversified)
        self.assertIn("def size(self):", diversified)


class DiversifyDeterminismTests(unittest.TestCase):
    def test_same_seed_is_deterministic(self):
        source = textwrap.dedent(
            """
            def compute(n):
                total = 0
                for i in range(n):
                    total += i
                return total
            """
        )
        first = diversify_source(source, "install-seed-123")
        second = diversify_source(source, "install-seed-123")
        self.assertEqual(first, second)

    def test_different_seeds_diverge(self):
        source = textwrap.dedent(
            """
            def compute(n):
                total = 0
                for i in range(n):
                    total += i
                return total
            """
        )
        first = diversify_source(source, "install-seed-a")
        second = diversify_source(source, "install-seed-b")
        self.assertNotEqual(first, second)


if __name__ == "__main__":
    unittest.main()
