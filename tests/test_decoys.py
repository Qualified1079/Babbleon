import tempfile
import unittest
from pathlib import Path
from unittest import mock

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
        # Isolate the wordbank-driven part of the content (the DB host)
        # rather than comparing whole strings -- every build also embeds
        # a fresh random honeytoken, which would make this assertion
        # trivially true even if wordbank.pick() always returned the
        # same word.
        hosts = set()
        for _ in range(20):
            _, content, _ = decoys.LeakedEnvPack().build()
            for line in content.splitlines():
                if line.startswith("DATABASE_URL="):
                    hosts.add(line.split("@", 1)[1].split(":", 1)[0])
        self.assertGreater(len(hosts), 1)

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

    def test_candidate_paths_first_is_original_then_random_suffixes(self):
        gen = decoys._candidate_paths("config/.env.qa.bak")
        first = next(gen)
        second = next(gen)
        third = next(gen)
        self.assertEqual(first, "config/.env.qa.bak")
        self.assertTrue(second.startswith("config/.env.qa-") and second.endswith(".bak"))
        self.assertNotEqual(second, third)

    class _FixedPathPack(decoys.DecoyPack):
        name = "fixed"

        def build(self, callback_base_url=None):
            return "config/.env.qa.bak", "fresh content\n", []

    def test_write_pack_loops_past_multiple_collisions(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "config").mkdir()
            (root / "config" / ".env.qa.bak").write_text("existing 1\n")
            (root / "config" / ".env.qa-aaaa.bak").write_text("existing 2\n")

            with mock.patch(
                "babbleon.decoys.secrets.token_hex", side_effect=["aaaa", "bbbb"]
            ):
                rel_path, _ = decoys.write_pack(root, self._FixedPathPack())

            self.assertEqual(rel_path, "config/.env.qa-bbbb.bak")
            self.assertEqual((root / rel_path).read_text(), "fresh content\n")
            # neither pre-existing file was touched
            self.assertEqual((root / "config/.env.qa.bak").read_text(), "existing 1\n")
            self.assertEqual((root / "config/.env.qa-aaaa.bak").read_text(), "existing 2\n")

    def test_write_pack_raises_after_collision_budget_exhausted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "config").mkdir()
            (root / "config" / ".env.qa.bak").write_text("existing\n")
            (root / "config" / ".env.qa-zzzz.bak").write_text("existing too\n")

            with mock.patch(
                "babbleon.decoys.secrets.token_hex", return_value="zzzz"
            ):
                with self.assertRaises(RuntimeError):
                    decoys.write_pack(root, self._FixedPathPack())

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
