"""Tests for zeitwerk.publisher — publishing and recovery of epoch data.

Runs with the stdlib: `python3 -m unittest discover tests`.
"""

import tempfile
import unittest
from pathlib import Path

import zeitwerk  # noqa: F401  (runs the python-opentimestamps path shim)
from zeitwerk.publisher import (
    epoch_path,
    epoch_of_path,
    write_epoch,
    write_signer,
    read_epoch,
    verify_published,
)


class EpochPathTests(unittest.TestCase):
    """Tests for epoch_path and epoch_of_path."""

    def test_epoch_path_0(self):
        self.assertEqual(epoch_path(0), "epochs/1970/01/01/00")

    def test_epoch_path_7(self):
        self.assertEqual(epoch_path(7), "epochs/1970/01/01/07")

    def test_round_trip(self):
        self.assertEqual(epoch_of_path(epoch_path(42)), 42)


class WriteEpochTests(unittest.TestCase):
    """Tests for write_epoch and read_epoch."""

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp())

    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_write_and_read_round_trip(self):
        """write_epoch then read_epoch returns the same data."""
        import hashlib
        digests = [hashlib.sha256(i.to_bytes(4, "big")).digest() for i in range(3)]
        from zeitwerk.epochtree import build_epoch_tree, encode_leaf_set
        tree = build_epoch_tree(digests)
        leaf_set = encode_leaf_set(tree.leaves)
        attestation = b"test_attestation"

        write_epoch(self.temp_dir, 7, leaf_set, attestation)
        read_leaf_set, read_root, read_attestation = read_epoch(self.temp_dir, 7)

        self.assertEqual(read_leaf_set, leaf_set)
        self.assertEqual(read_root, tree.root)
        self.assertEqual(read_attestation, attestation)


class WriteSignerTests(unittest.TestCase):
    """Tests for write_signer."""

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp())

    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_write_signer_creates_files(self):
        from zeitwerk.signer import Signer, key_id_of
        signer = Signer()
        pubkey = signer.public_key

        key_id = write_signer(self.temp_dir, pubkey)
        self.assertEqual(key_id, key_id_of(pubkey))
        self.assertTrue((self.temp_dir / "signers" / f"{key_id.hex()}.pub").exists())
        self.assertTrue((self.temp_dir / "signers" / f"{key_id.hex()}.json").exists())


class VerifyPublishedTests(unittest.TestCase):
    """Tests for verify_published."""

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp())

    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_verify_included_digest(self):
        """verify_published returns True for an included digest."""
        import hashlib
        digests = [hashlib.sha256(i.to_bytes(4, "big")).digest() for i in range(3)]
        from zeitwerk.epochtree import build_epoch_tree, encode_leaf_set
        from zeitwerk.signer import Signer
        tree = build_epoch_tree(digests)
        leaf_set = encode_leaf_set(tree.leaves)
        signer = Signer()

        write_epoch(self.temp_dir, 7, leaf_set, b"attestation")
        write_signer(self.temp_dir, signer.public_key)

        self.assertTrue(verify_published(self.temp_dir, digests[0], 7))


if __name__ == "__main__":
    unittest.main()
