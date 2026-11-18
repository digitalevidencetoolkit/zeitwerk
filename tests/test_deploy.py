"""Tests for deploy/update.sh, which updates a witness in place.

It runs against a stand-in for /opt/zeitwerk: a small git project whose
`make setup` leaves a mark, a fake `systemctl` on PATH that logs what it is
asked, and the witness's public key served from a file (ZEITWERK_URL can be
a file:// URL, which curl reads like any other).
"""

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "deploy" / "update.sh"
HAS_TOOLS = all(shutil.which(tool) for tool in ("git", "make", "curl", "od"))
KEY = b"\x01" * 32

# A restart puts FAKE_NEXT_KEY in place, if there is one: a witness that came back with another key.
FAKE_SYSTEMCTL = """#!/bin/sh
echo "$*" >> "$FAKE_SYSTEMCTL_LOG"
if [ "$1" = restart ] && [ -f "$FAKE_NEXT_KEY" ]; then
    cp "$FAKE_NEXT_KEY" "$FAKE_KEY"
fi
"""
GIT = ["git", "-c", "user.name=test", "-c", "user.email=test@example.org", "-c", "commit.gpgsign=false"]


@unittest.skipUnless(HAS_TOOLS, "needs git, make, curl and od")
class UpdateScriptTests(unittest.TestCase):
    def setUp(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        self.origin, self.box, witness, bin_dir = tmp / "origin", tmp / "box", tmp / "witness", tmp / "bin"
        for folder in (self.origin, witness, bin_dir):
            folder.mkdir()

        self._git(self.origin, "init", "-q", "-b", "main")
        (self.origin / "Makefile").write_text("setup:\n\ttouch .setup-ran\n")
        self.first = self._commit("First version")
        self.second = self._commit("Second version")
        self._git(tmp, "clone", "-q", str(self.origin), str(self.box))
        self._git(self.box, "checkout", "-q", "--detach", self.first)

        self.key, self.next_key, self.status = witness / "key", tmp / "next-key", witness / "status.json"
        self.key.write_bytes(KEY)
        systemctl = bin_dir / "systemctl"
        systemctl.write_text(FAKE_SYSTEMCTL)
        systemctl.chmod(0o755)
        self.systemctl_log = tmp / "systemctl.log"
        self.env = {
            **os.environ,
            "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
            "ZEITWERK_DIR": str(self.box),
            "ZEITWERK_SERVICE": "witness",
            "ZEITWERK_URL": witness.as_uri(),
            "FAKE_SYSTEMCTL_LOG": str(self.systemctl_log),
            "FAKE_KEY": str(self.key),
            "FAKE_NEXT_KEY": str(self.next_key),
        }

    def _git(self, repo, *args):
        return subprocess.run(
            [*GIT, "-C", str(repo), *args], check=True, capture_output=True, text=True
        ).stdout.strip()

    def _commit(self, subject):
        (self.origin / "version").write_text(subject)
        self._git(self.origin, "add", "version", "Makefile")
        self._git(self.origin, "commit", "-q", "-m", subject)
        return self._git(self.origin, "rev-parse", "HEAD")

    def _update(self, *args):
        return subprocess.run(
            ["sh", str(SCRIPT), *args], env=self.env, capture_output=True, text=True, timeout=60
        )

    def _head(self):
        return self._git(self.box, "rev-parse", "HEAD")

    def _systemctl_calls(self):
        return self.systemctl_log.read_text().splitlines() if self.systemctl_log.exists() else []

    def test_a_dry_run_lists_what_would_change_and_changes_nothing(self):
        result = self._update("--dry-run")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("+ ", result.stdout)
        self.assertIn("Second version", result.stdout)
        self.assertEqual(self._head(), self.first)
        self.assertEqual(self._systemctl_calls(), [])

    def test_an_update_checks_out_main_runs_setup_and_restarts(self):
        result = self._update()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self._head(), self.second)
        self.assertTrue((self.box / ".setup-ran").exists())
        self.assertEqual(self._systemctl_calls(), ["restart witness"])

    def test_going_back_to_an_older_commit_lists_what_it_undoes(self):
        self._update()
        result = self._update(self.first)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("- ", result.stdout)
        self.assertIn("Second version", result.stdout)
        self.assertEqual(self._head(), self.first)

    def test_already_there_is_a_no_op(self):
        self._update()
        result = self._update()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("nothing to do", result.stdout)
        self.assertEqual(self._systemctl_calls(), ["restart witness"])  # the first update's only

    def test_local_changes_are_refused(self):
        (self.box / "version").write_text("edited on the box")
        result = self._update()
        self.assertEqual(result.returncode, 1)
        self.assertIn("local changes", result.stderr)
        self.assertEqual(self._head(), self.first)

    def test_an_unknown_ref_is_refused(self):
        result = self._update("no-such-branch")
        self.assertEqual(result.returncode, 1)
        self.assertIn("no-such-branch", result.stderr)
        self.assertEqual(self._head(), self.first)


    def test_after_the_restart_it_checks_the_key_is_the_same(self):
        result = self._update()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("key 01010101", result.stdout)

    def test_a_changed_key_stops_the_witness(self):
        """It came back without its signing key: better stopped than signing as someone else."""
        self.next_key.write_bytes(b"\x02" * 32)
        result = self._update()
        self.assertEqual(result.returncode, 1)
        self.assertIn("key changed", result.stderr)
        self.assertEqual(self._systemctl_calls(), ["restart witness", "stop witness"])

    def test_a_witness_that_was_down_has_no_key_to_compare_but_still_updates(self):
        self.key.unlink()
        self.next_key.write_bytes(KEY)
        result = self._update()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("no key to compare", result.stdout)
        self.assertIn("key 01010101", result.stdout)

    def test_it_says_whether_the_witness_is_caught_up(self):
        self.status.write_text('{"caught_up": true, "to_seal": 0}')
        self.assertIn("all caught up", self._update().stdout)

    def test_a_version_without_a_status_page_says_so(self):
        self.assertIn("no status page", self._update().stdout)


if __name__ == "__main__":
    unittest.main()
