import tempfile
import unittest
from pathlib import Path

from babbleon import honeytoken as ht
from babbleon.errors import BabbleonError
from babbleon.registry import Registry


class RegistryTests(unittest.TestCase):
    def test_add_and_save_persists_across_instances(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            reg = Registry(root)
            token = ht.make_api_key()
            reg.add("config/.env.bak", "leaked_env", [token])
            reg.save()

            reloaded = Registry(root)
            self.assertEqual(len(reloaded.entries), 1)
            self.assertEqual(reloaded.entries[0]["path"], "config/.env.bak")

    def test_find_by_value_substring_matches_partial_leak(self):
        with tempfile.TemporaryDirectory() as tmp:
            reg = Registry(Path(tmp))
            token = ht.make_api_key()
            reg.add("config/.env.bak", "leaked_env", [token])
            partial = token.value[5:15]
            hits = reg.find_by_value_substring(partial)
            self.assertEqual(len(hits), 1)

    def test_find_by_value_substring_no_match(self):
        with tempfile.TemporaryDirectory() as tmp:
            reg = Registry(Path(tmp))
            reg.add("config/.env.bak", "leaked_env", [ht.make_api_key()])
            hits = reg.find_by_value_substring("not-a-real-token")
            self.assertEqual(hits, [])

    def test_empty_needle_returns_no_hits(self):
        with tempfile.TemporaryDirectory() as tmp:
            reg = Registry(Path(tmp))
            self.assertEqual(reg.find_by_value_substring(""), [])

    def test_registry_file_lives_under_dot_babbleon(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            reg = Registry(root)
            reg.add("x", "leaked_env", [ht.make_api_key()])
            reg.save()
            self.assertTrue((root / ".babbleon" / "registry.json").exists())

    def test_is_decoy_matches_relative_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            reg = Registry(root)
            reg.add("internal/legacy_admin.py", "legacy_admin", [ht.make_admin_override()])
            self.assertTrue(reg.is_decoy("internal/legacy_admin.py"))
            self.assertFalse(reg.is_decoy("internal/real_admin.py"))

    def test_is_decoy_matches_absolute_path_under_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            reg = Registry(root)
            reg.add("internal/legacy_admin.py", "legacy_admin", [ht.make_admin_override()])
            absolute = root / "internal" / "legacy_admin.py"
            self.assertTrue(reg.is_decoy(absolute))

    def test_is_decoy_false_for_path_outside_root(self):
        with tempfile.TemporaryDirectory() as tmp_a, tempfile.TemporaryDirectory() as tmp_b:
            reg = Registry(Path(tmp_a))
            reg.add("internal/legacy_admin.py", "legacy_admin", [ht.make_admin_override()])
            outside = Path(tmp_b) / "internal" / "legacy_admin.py"
            self.assertFalse(reg.is_decoy(outside))

    def test_is_decoy_normalizes_non_canonical_relative_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            reg = Registry(root)
            reg.add("internal/legacy_admin.py", "legacy_admin", [ht.make_admin_override()])
            self.assertTrue(reg.is_decoy("internal/../internal/legacy_admin.py"))
            self.assertTrue(reg.is_decoy("./internal/legacy_admin.py"))
            self.assertFalse(reg.is_decoy("../outside.py"))

    def test_corrupted_registry_raises_clear_runtime_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".babbleon").mkdir()
            (root / ".babbleon" / "registry.json").write_text("{not valid json")
            with self.assertRaises(BabbleonError) as ctx:
                Registry(root)
            self.assertIn("not valid JSON", str(ctx.exception))
            self.assertNotIn("Traceback", str(ctx.exception))

    def test_non_dict_json_raises_clear_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".babbleon").mkdir()
            (root / ".babbleon" / "registry.json").write_text("[]")
            with self.assertRaises(BabbleonError) as ctx:
                Registry(root)
            self.assertIn("not a babbleon registry", str(ctx.exception))

    def test_non_list_entries_field_raises_clear_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".babbleon").mkdir()
            (root / ".babbleon" / "registry.json").write_text(
                '{"version": 1, "entries": "oops"}'
            )
            with self.assertRaises(BabbleonError):
                Registry(root)

    def test_context_manager_reloads_under_lock_before_mutating(self):
        # Simulates a second process writing to the registry between this
        # Registry's unlocked __init__ load and the point where it's used
        # inside a `with` block -- __enter__ must reload under the lock
        # rather than silently working from the stale __init__ snapshot
        # and clobbering the other write on save.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            reg = Registry(root)  # sees an empty registry

            other = Registry(root)
            other.add("other/file.py", "legacy_admin", [ht.make_admin_override()])
            other.save()  # registry.json now has 1 entry reg doesn't know about

            with reg as locked:
                self.assertEqual(len(locked.entries), 1)
                locked.add("mine/file.py", "legacy_admin", [ht.make_admin_override()])

            final = Registry(root)
            self.assertEqual(len(final.entries), 2)

    def test_context_manager_saves_even_on_exception(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with self.assertRaises(ValueError):
                with Registry(root) as reg:
                    reg.add("mine/file.py", "legacy_admin", [ht.make_admin_override()])
                    raise ValueError("something else went wrong mid-loop")
            reloaded = Registry(root)
            self.assertEqual(len(reloaded.entries), 1)


if __name__ == "__main__":
    unittest.main()
