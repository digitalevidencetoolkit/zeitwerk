"""Tests for zeitwerk.status — what the status page shows.

Runs with the stdlib: `python3 -m unittest discover tests`.
"""

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import zeitwerk  # noqa: F401  (runs the python-opentimestamps path shim)
from zeitwerk.gitrepo import ensure_repo, set_remote
from zeitwerk.signer import Signer
from zeitwerk.status import HOURS_SHOWN, web_url, witness_status
from zeitwerk.store import Store
from zeitwerk.witness import EPOCH_SECONDS, close_due, publish_due

HAS_GIT = shutil.which("git") is not None
NOW = 100 * EPOCH_SECONDS + 12  # twelve seconds into epoch 100
DIGEST = b"\x01" * 32


class WebUrlTests(unittest.TestCase):
    def test_an_scp_style_ssh_remote_becomes_its_https_page(self):
        self.assertEqual(
            web_url("git@github.com:digitalevidencetoolkit/zeitwerk-epochs.git"),
            "https://github.com/digitalevidencetoolkit/zeitwerk-epochs",
        )

    def test_an_ssh_url_becomes_its_https_page(self):
        self.assertEqual(
            web_url("ssh://git@codeberg.org/digitalevidencetoolkit/zeitwerk-epochs.git"),
            "https://codeberg.org/digitalevidencetoolkit/zeitwerk-epochs",
        )

    def test_credentials_and_port_in_an_https_url_are_dropped(self):
        self.assertEqual(
            web_url("https://user:token@gitlab.example.org:8443/org/epochs.git"),
            "https://gitlab.example.org/org/epochs",
        )

    def test_a_local_path_has_no_page(self):
        self.assertIsNone(web_url("/srv/mirrors/epochs.git"))
        self.assertIsNone(web_url("file:///srv/mirrors/epochs.git"))


@unittest.skipUnless(HAS_GIT, "git not available")
class StatusTests(unittest.TestCase):
    def setUp(self):
        self.store = Store(":memory:")
        self.addCleanup(self.store.close)
        self.signer = Signer()
        self.repo = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(self.repo, ignore_errors=True))
        ensure_repo(self.repo)

    def _status(self, now=NOW):
        return witness_status(self.store, self.signer, self.repo, now, started=NOW - 60)

    def _hour_states(self, now=NOW):
        return [(hour["epoch"], hour["state"]) for hour in self._status(now)["hours"]]

    def test_a_fresh_witness_is_caught_up_with_nothing_in_it(self):
        result = self._status()
        self.assertEqual(result["epoch"], 100)
        self.assertEqual(result["signers"], [self.signer.key_id.hex()])
        self.assertEqual((result["fingerprints"], result["hours"], result["mirrors"]), (0, [], []))
        self.assertTrue(result["caught_up"])

    def test_the_current_hour_is_open_and_still_caught_up(self):
        self.store.add_submission(DIGEST, 100)
        result = self._status()
        self.assertEqual(result["hours"], [{"epoch": 100, "fingerprints": 1, "state": "open"}])
        self.assertTrue(result["caught_up"])

    def test_a_finished_hour_waits_to_be_sealed(self):
        self.store.add_submission(DIGEST, 99)
        result = self._status()
        self.assertEqual(self._hour_states(), [(99, "sealing")])
        self.assertEqual(result["to_seal"], 1)
        self.assertFalse(result["caught_up"])

    def test_a_sealed_hour_waits_to_be_published(self):
        self.store.add_submission(DIGEST, 99)
        close_due(self.store, self.signer, NOW)
        result = self._status()
        self.assertEqual(self._hour_states(), [(99, "sealed")])
        self.assertEqual((result["hours_sealed"], result["to_publish"]), (1, 1))
        self.assertFalse(result["caught_up"])

    def test_a_published_hour_with_no_mirrors_is_caught_up(self):
        self.store.add_submission(DIGEST, 99)
        close_due(self.store, self.signer, NOW)
        publish_due(self.store, self.signer, self.repo)
        result = self._status()
        self.assertEqual(self._hour_states(), [(99, "published")])
        self.assertEqual(result["hours_published"], 1)
        self.assertTrue(result["caught_up"])

    def test_hours_before_the_window_are_left_out_but_still_counted(self):
        self.store.add_submission(DIGEST, 100 - HOURS_SHOWN)
        self.store.add_submission(DIGEST, 100 - HOURS_SHOWN + 1)
        result = self._status()
        self.assertEqual([hour["epoch"] for hour in result["hours"]], [100 - HOURS_SHOWN + 1])
        self.assertEqual(result["fingerprints"], 2)

    def test_a_mirror_shows_its_kind_its_page_and_what_it_is_missing(self):
        self.store.add_submission(DIGEST, 99)
        close_due(self.store, self.signer, NOW)
        publish_due(self.store, self.signer, self.repo)
        set_remote(self.repo, "codeberg", "ssh://git@codeberg.org/org/epochs.git")  # after: no real push
        result = self._status()
        self.assertEqual(
            result["mirrors"],
            [{"name": "codeberg", "kind": "Codeberg", "url": "https://codeberg.org/org/epochs",
              "unpushed": 1, "last_pushed": None}],
        )
        self.assertFalse(result["caught_up"])

    def test_a_mirror_on_an_unknown_host_is_named_by_its_host(self):
        set_remote(self.repo, "lib", "git@git.library.example:epochs.git")
        self.assertEqual(self._status()["mirrors"][0]["kind"], "git.library.example")

    def test_a_mirror_on_a_local_path_has_no_page(self):
        set_remote(self.repo, "backup", "/srv/epochs.git")
        [mirror] = self._status()["mirrors"]
        self.assertEqual((mirror["kind"], mirror["url"]), ("local", None))

    def test_unreadable_mirrors_are_unknown_not_caught_up(self):
        broken = subprocess.CalledProcessError(128, "git", stderr="fatal: not a git repository")
        with mock.patch("zeitwerk.status.remote_status", side_effect=broken), self.assertLogs(level="ERROR"):
            result = self._status()
        self.assertIsNone(result["mirrors"])
        self.assertFalse(result["caught_up"])


if __name__ == "__main__":
    unittest.main()
