import tempfile
import unittest
from pathlib import Path

from babbleon import decoys
from babbleon import wordbank as wb


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

    def test_internal_notes_pack_uses_callback_base_url_when_given(self):
        _, content, tokens = decoys.InternalNotesPack().build(
            callback_base_url="https://hooks.example.com/x"
        )
        self.assertTrue(any(t.live for t in tokens))
        self.assertIn("hooks.example.com/x/babbleon/", content)

    def test_other_packs_ignore_callback_base_url(self):
        for pack_cls in (decoys.LeakedEnvPack, decoys.LegacyAdminPack):
            _, content, tokens = pack_cls().build(
                callback_base_url="https://hooks.example.com/x"
            )
            self.assertFalse(any(t.live for t in tokens))
            self.assertNotIn("hooks.example.com", content)

    def test_npm_registry_token_pack_shape(self):
        path, content, tokens = decoys.NpmRegistryTokenPack().build()
        self.assertTrue(path.endswith(".npmrc.bak"))
        self.assertEqual(len(tokens), 1)
        self.assertIn("_authToken=", content)
        self.assertIn(tokens[0].value, content)

    def test_ci_deploy_secrets_pack_shape(self):
        path, content, tokens = decoys.CiDeploySecretsPack().build()
        self.assertTrue(any(path.endswith(f) for f in wb.CI_FILENAMES))
        self.assertEqual(len(tokens), 2)
        self.assertIn("DEPLOY_TOKEN=", content)
        self.assertIn("DOCKER_REGISTRY_PASSWORD=", content)
        for t in tokens:
            self.assertIn(t.value, content)

    def test_all_pack_names_are_unique(self):
        names = [p.name for p in decoys.ALL_PACKS]
        self.assertEqual(len(names), len(set(names)))

    def test_paths_vary_across_repeated_builds(self):
        for pack_cls in decoys.ALL_PACKS:
            paths = {pack_cls().build()[0] for _ in range(25)}
            self.assertGreater(
                len(paths), 1, f"{pack_cls.name} always writes the same path"
            )

    def test_avoid_collision_renames_on_forced_clash(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "config").mkdir()
            (root / "config" / ".env.qa.bak").write_text("already here\n")
            renamed = decoys._avoid_collision(root, "config/.env.qa.bak")
            self.assertNotEqual(renamed, "config/.env.qa.bak")
            self.assertTrue(renamed.startswith("config/.env.qa-"))
            self.assertTrue(renamed.endswith(".bak"))

    def test_write_pack_twice_scatters_instead_of_overwriting(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path_a, tokens_a = decoys.write_pack(root, decoys.LeakedEnvPack())
            path_b, tokens_b = decoys.write_pack(root, decoys.LeakedEnvPack())
            self.assertTrue((root / path_a).exists())
            self.assertTrue((root / path_b).exists())
            # the first file must still contain its own token -- a real
            # collision must rename rather than silently clobber it
            self.assertIn(tokens_a[0].value, (root / path_a).read_text())


if __name__ == "__main__":
    unittest.main()
