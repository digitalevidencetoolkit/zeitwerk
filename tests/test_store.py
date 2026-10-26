"""Tests for the SQLite store (draft stubs)."""

import tempfile
import unittest
from pathlib import Path

from zeitwerk.store import Store

DIGEST = b"\x01" * 32
EPOCH = 7


class StoreOpenTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = Path(tmp.name) / "zeitwerk.db"

    def test_opening_creates_the_file(self):
        Store(self.path).close()
        self.assertTrue(self.path.exists())

    def test_reopening_an_existing_store_works(self):
        Store(self.path).close()
        Store(self.path).close()  # raises if the schema can't be applied twice


class StoreStubTests(unittest.TestCase):
    def setUp(self):
        self.store = Store(":memory:")
        self.addCleanup(self.store.close)

    def test_add_submission_is_not_implemented(self):
        with self.assertRaises(NotImplementedError):
            self.store.add_submission(DIGEST, EPOCH)

    def test_is_submitted_is_not_implemented(self):
        with self.assertRaises(NotImplementedError):
            self.store.is_submitted(DIGEST)

    def test_close_epoch_is_not_implemented(self):
        with self.assertRaises(NotImplementedError):
            self.store.close_epoch(EPOCH)

    def test_seal_epoch_is_not_implemented(self):
        with self.assertRaises(NotImplementedError):
            self.store.seal_epoch(EPOCH, b"\x02" * 32, b"")


if __name__ == "__main__":
    unittest.main()
