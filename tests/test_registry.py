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


if __name__ == "__main__":
    unittest.main()
