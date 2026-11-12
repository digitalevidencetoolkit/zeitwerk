"""Tests for zeitwerk.gitrepo — thin git CLI wrapper.

Tests are skipped if git is not available on the system.
"""

import shutil
import tempfile
import unittest
from pathlib import Path

import zeitwerk  # noqa: F401  (runs the python-opentimestamps path shim)

from zeitwerk.gitrepo import commit, ensure_repo
HAS_GIT = shutil.which("git") is not None


@unittest.skipUnless(HAS_GIT, "git not available")
class GitRepoTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(self.temp_dir, ignore_errors=True))

    def test_ensure_repo_creates_a_new_repo(self):
        ensure_repo(self.temp_dir)
        self.assertTrue((self.temp_dir / ".git").exists())

    def test_ensure_repo_leaves_existing_repo_alone(self):
        ensure_repo(self.temp_dir)
        ensure_repo(self.temp_dir)  # second call should not fail
        self.assertTrue((self.temp_dir / ".git").exists())

    def test_commit_returns_false_when_nothing_to_commit(self):
        ensure_repo(self.temp_dir)
        self.assertFalse(commit(self.temp_dir, 7))

    def test_commit_creates_a_commit(self):
        ensure_repo(self.temp_dir)
        # Create a file to commit in the proper epoch folder
        from zeitwerk.publisher import epoch_path
        epoch_folder = self.temp_dir / epoch_path(7)
        epoch_folder.mkdir(parents=True)
        (epoch_folder / "leaves.bin").write_text("test")
        self.assertTrue(commit(self.temp_dir, 7))

    def test_commit_message_format(self):
        ensure_repo(self.temp_dir)
        from zeitwerk.publisher import epoch_path
        epoch_folder = self.temp_dir / epoch_path(7)
        epoch_folder.mkdir(parents=True)
        (epoch_folder / "leaves.bin").write_text("test")
        commit(self.temp_dir, 7)
        # Check the commit message
        import subprocess
        result = subprocess.run(
            ["git", "-C", str(self.temp_dir), "log", "-1", "--pretty=%B"],
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.stdout.strip(), "epoch 7 (1970-01-01 07:00 UTC)")

    def test_second_commit_is_a_no_op(self):
        ensure_repo(self.temp_dir)
        from zeitwerk.publisher import epoch_path
        epoch_folder = self.temp_dir / epoch_path(7)
        epoch_folder.mkdir(parents=True)
        (epoch_folder / "leaves.bin").write_text("test")
        commit(self.temp_dir, 7)
        self.assertFalse(commit(self.temp_dir, 7))

    def test_unrelated_file_not_in_commit(self):
        """An unrelated file at the repo root should not be swept into the commit."""
        ensure_repo(self.temp_dir)
        # Create epoch folder using the proper path
        from zeitwerk.publisher import epoch_path
        epoch_folder = self.temp_dir / epoch_path(7)
        epoch_folder.mkdir(parents=True)
        (epoch_folder / "leaves.bin").write_text("test")
        # Create an unrelated file at repo root
        (self.temp_dir / "unrelated.txt").write_text("should not be committed")
        
        # Commit the epoch
        commit(self.temp_dir, 7)
        
        # Check that unrelated.txt is not in the commit
        import subprocess
        result = subprocess.run(
            ["git", "-C", str(self.temp_dir), "show", "--name-only", "--pretty=format:"],
            check=True,
            capture_output=True,
            text=True,
        )
        committed_files = result.stdout.strip().split('\n')
        self.assertNotIn("unrelated.txt", committed_files)
        # The epoch folder should be in the commit
        self.assertTrue(any("epochs" in f for f in committed_files))


if __name__ == "__main__":
    unittest.main()
