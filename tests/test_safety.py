import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from babbleon import cli, safety
from babbleon.registry import Registry
from babbleon import honeytoken as ht

BABBLEON_REPO_ROOT = Path(__file__).resolve().parent.parent


def _git(root, *args):
    return subprocess.run(
        ["git", "-C", str(root), *args],
        capture_output=True,
        text=True,
        check=True,
    )


def _init_repo(root: Path):
    _git(root, "init", "-q")
    _git(root, "config", "user.email", "test@example.com")
    _git(root, "config", "user.name", "Test")


class SafetyCheckTests(unittest.TestCase):
    def test_non_git_dir_is_always_clean(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(safety.check(Path(tmp)), [])

    def test_clean_repo_with_gitignore_has_no_problems(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _init_repo(root)
            (root / ".gitignore").write_text(".babbleon/\n")
            reg = Registry(root)
            reg.add("config/.env.bak", "leaked_env", [ht.make_api_key()])
            reg.save()
            self.assertEqual(safety.check(root), [])

    def test_missing_gitignore_is_flagged(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _init_repo(root)
            reg = Registry(root)
            reg.add("config/.env.bak", "leaked_env", [ht.make_api_key()])
            reg.save()
            problems = safety.check(root)
            self.assertTrue(any("not gitignored" in p for p in problems))

    def test_staged_registry_file_is_flagged(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _init_repo(root)
            (root / ".gitignore").write_text("")  # doesn't cover .babbleon
            reg = Registry(root)
            reg.add("config/.env.bak", "leaked_env", [ht.make_api_key()])
            reg.save()
            _git(root, "add", "-f", ".babbleon/registry.json")
            problems = safety.check(root)
            self.assertTrue(any("staged" in p for p in problems))

    def test_staged_with_correct_gitignore_does_not_also_claim_not_ignored(self):
        # git check-ignore reports a path as *not* ignored once it's
        # already in the index, regardless of .gitignore content -- so
        # once "staged" already explains the problem, "not gitignored"
        # would be misleading (and wrong) remediation advice.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _init_repo(root)
            (root / ".gitignore").write_text(".babbleon/\n")
            reg = Registry(root)
            reg.add("config/.env.bak", "leaked_env", [ht.make_api_key()])
            reg.save()
            _git(root, "add", "-f", ".babbleon/registry.json")
            problems = safety.check(root)
            self.assertTrue(any("staged" in p for p in problems))
            self.assertFalse(any("not gitignored" in p for p in problems))

    def test_tracked_registry_file_is_flagged(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _init_repo(root)
            reg = Registry(root)
            reg.add("config/.env.bak", "leaked_env", [ht.make_api_key()])
            reg.save()
            _git(root, "add", "-f", ".babbleon/registry.json")
            _git(root, "commit", "-q", "-m", "oops")
            problems = safety.check(root)
            self.assertTrue(any("tracked by git" in p for p in problems))


class CliCheckAndHookTests(unittest.TestCase):
    def test_check_command_ok_and_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _init_repo(root)
            (root / ".gitignore").write_text(".babbleon/\n")
            rc = cli.main(["--path", str(root), "seed"])
            self.assertEqual(rc, 0)
            rc = cli.main(["--path", str(root), "check"])
            self.assertEqual(rc, 0)

            _git(root, "add", "-f", ".babbleon/registry.json")
            rc = cli.main(["--path", str(root), "check"])
            self.assertEqual(rc, 1)

    def test_install_hook_writes_executable_pre_commit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _init_repo(root)
            rc = cli.main(["--path", str(root), "install-hook"])
            self.assertEqual(rc, 0)
            hook_path = root / ".git" / "hooks" / "pre-commit"
            self.assertTrue(hook_path.exists())
            self.assertIn(cli.PRE_COMMIT_MARKER, hook_path.read_text())
            self.assertTrue(hook_path.stat().st_mode & 0o111)

    def test_install_hook_is_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _init_repo(root)
            cli.main(["--path", str(root), "install-hook"])
            hook_path = root / ".git" / "hooks" / "pre-commit"
            first = hook_path.read_text()
            rc = cli.main(["--path", str(root), "install-hook"])
            self.assertEqual(rc, 0)
            self.assertEqual(hook_path.read_text(), first)

    def test_install_hook_outside_git_repo_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            rc = cli.main(["--path", tmp, "install-hook"])
            self.assertEqual(rc, 1)


class HookExecutionTests(unittest.TestCase):
    """Actually run `git commit` with the installed hook, as a real shell
    script would -- not just calling cli.main() in-process."""

    def _setup_repo_with_staged_registry_leak(self, root: Path):
        _init_repo(root)
        cli.main(["--path", str(root), "install-hook"])
        (root / ".gitignore").write_text("")  # deliberately doesn't cover .babbleon
        reg = Registry(root)
        reg.add("config/.env.bak", "leaked_env", [ht.make_api_key()])
        reg.save()
        _git(root, "add", "-A")
        _git(root, "add", "-f", ".babbleon/registry.json")

    def test_hook_blocks_commit_when_babbleon_importable(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._setup_repo_with_staged_registry_leak(root)
            env = dict(os.environ)
            env["PYTHONPATH"] = str(BABBLEON_REPO_ROOT)
            result = subprocess.run(
                ["git", "-C", str(root), "commit", "-q", "-m", "oops"],
                capture_output=True,
                text=True,
                env=env,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("aborting commit", result.stderr)

    def test_hook_fails_open_when_babbleon_not_importable(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._setup_repo_with_staged_registry_leak(root)
            env = dict(os.environ)
            env.pop("PYTHONPATH", None)
            result = subprocess.run(
                ["git", "-C", str(root), "commit", "-q", "-m", "allowed anyway"],
                capture_output=True,
                text=True,
                cwd=str(root),
                env=env,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("guard skipped", result.stderr)


if __name__ == "__main__":
    unittest.main()
