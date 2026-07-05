import tempfile
import unittest
from pathlib import Path

from babbleon import honeytoken as ht
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
            with self.assertRaises(RuntimeError) as ctx:
                Registry(root)
            self.assertIn("not valid JSON", str(ctx.exception))
            self.assertNotIn("Traceback", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
