import tempfile
import unittest
from pathlib import Path

from babbleon import cli
from babbleon.registry import Registry


class CliTests(unittest.TestCase):
    def test_seed_then_list_then_verify_then_clean(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            rc = cli.main(["--path", str(root), "seed"])
            self.assertEqual(rc, 0)

            reg = Registry(root)
            self.assertEqual(len(reg.entries), 3)
            for entry in reg.entries:
                self.assertTrue((root / entry["path"]).exists())

            leaked_value = reg.entries[0]["tokens"][0]["value"]
            rc = cli.main(["--path", str(root), "verify", leaked_value])
            self.assertEqual(rc, 0)

            rc = cli.main(["--path", str(root), "verify", "definitely-not-planted"])
            self.assertEqual(rc, 1)

            rc = cli.main(["--path", str(root), "clean"])
            self.assertEqual(rc, 0)
            reg2 = Registry(root)
            self.assertEqual(reg2.entries, [])
            for entry in reg.entries:
                self.assertFalse((root / entry["path"]).exists())

    def test_seed_specific_pack_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            rc = cli.main(["--path", str(root), "seed", "legacy_admin"])
            self.assertEqual(rc, 0)
            reg = Registry(root)
            self.assertEqual(len(reg.entries), 1)
            self.assertEqual(reg.entries[0]["pack"], "legacy_admin")

    def test_seed_unknown_pack_returns_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            rc = cli.main(["--path", tmp, "seed", "nonexistent_pack"])
            self.assertEqual(rc, 1)

    def test_list_with_no_decoys(self):
        with tempfile.TemporaryDirectory() as tmp:
            rc = cli.main(["--path", tmp, "list"])
            self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
