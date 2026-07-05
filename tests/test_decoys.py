import tempfile
import unittest
from pathlib import Path

from babbleon import decoys


class DecoyPackTests(unittest.TestCase):
    def test_all_packs_build_valid_tuple(self):
        for pack_cls in decoys.ALL_PACKS:
            pack = pack_cls()
            rel_path, content, tokens = pack.build()
            self.assertTrue(rel_path)
            self.assertTrue(content)
            self.assertTrue(tokens)
            for t in tokens:
                self.assertIn(t.value, content)

    def test_write_pack_creates_file_on_disk(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pack = decoys.LeakedEnvPack()
            rel_path, tokens = decoys.write_pack(root, pack)
            full_path = root / rel_path
            self.assertTrue(full_path.exists())
            text = full_path.read_text()
            for t in tokens:
                self.assertIn(t.value, text)

    def test_randomization_varies_across_builds(self):
        samples = {decoys.LeakedEnvPack().build()[1] for _ in range(20)}
        self.assertGreater(len(samples), 1)

    def test_legacy_admin_pack_is_syntactically_valid_python(self):
        _, content, _ = decoys.LegacyAdminPack().build()
        compile(content, "<legacy_admin_decoy>", "exec")


if __name__ == "__main__":
    unittest.main()
