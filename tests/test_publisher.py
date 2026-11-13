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

    def _leaf_set(self):
        import hashlib
        from zeitwerk.epochtree import build_epoch_tree, encode_leaf_set
        digests = [hashlib.sha256(i.to_bytes(4, "big")).digest() for i in range(3)]
        return encode_leaf_set(build_epoch_tree(digests).leaves)

    def test_a_torn_write_is_repaired_on_the_next_call(self):
        """A truncated or empty file left by a crash is rewritten, not a permanent conflict."""
        from zeitwerk.publisher import epoch_path
        leaf_set = self._leaf_set()
        folder = self.temp_dir / epoch_path(7)
        folder.mkdir(parents=True)
        (folder / "leaves.bin").write_bytes(leaf_set[:5])
        (folder / "attestation").write_bytes(b"")
        write_epoch(self.temp_dir, 7, leaf_set, b"test_attestation")
        self.assertEqual(read_epoch(self.temp_dir, 7)[0], leaf_set)
        self.assertEqual(sorted(p.name for p in folder.glob("*.tmp")), [])

    def test_different_content_is_still_a_conflict(self):
        from zeitwerk.publisher import epoch_path
        folder = self.temp_dir / epoch_path(7)
        folder.mkdir(parents=True)
        (folder / "attestation").write_bytes(b"another")
        with self.assertRaises(ValueError):
            write_epoch(self.temp_dir, 7, self._leaf_set(), b"test_attestation")


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
    """verify_published: the third-party check, from the published folder and signers/ alone."""

    EPOCH = 7

    def setUp(self):
        import hashlib
        import shutil
        from zeitwerk.epochtree import build_epoch_tree, encode_leaf_set
        from zeitwerk.signer import Signer

        self.temp_dir = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(self.temp_dir, ignore_errors=True))
        self.digests = [hashlib.sha256(i.to_bytes(4, "big")).digest() for i in range(3)]
        tree = build_epoch_tree(self.digests)
        self.leaf_set = encode_leaf_set(tree.leaves)
        self.root = tree.root
        self.signer = Signer()

    def _publish(self, attestation_epoch=EPOCH, root=None, signer=None):
        """Write the epoch, signed as the witness does it, plus the signer's key."""
        from zeitwerk.attestation import serialize_attestation
        from zeitwerk.witness import signed_attestation

        signer = signer or self.signer
        attestation = signed_attestation(signer, attestation_epoch, root or self.root)
        write_epoch(self.temp_dir, self.EPOCH, self.leaf_set, serialize_attestation(attestation))
        write_signer(self.temp_dir, self.signer.public_key)

    def test_verify_included_digest(self):
        self._publish()
        self.assertTrue(verify_published(self.temp_dir, self.digests[0], self.EPOCH))

    def test_a_digest_not_in_the_set_fails(self):
        self._publish()
        with self.assertRaisesRegex(ValueError, "not in epoch"):
            verify_published(self.temp_dir, b"\x00" * 32, self.EPOCH)

    def test_an_unknown_signer_fails(self):
        from zeitwerk.signer import Signer

        self._publish(signer=Signer())  # signed by a key that is not in signers/
        with self.assertRaisesRegex(ValueError, "not in signers/"):
            verify_published(self.temp_dir, self.digests[0], self.EPOCH)

    def test_a_signature_over_another_root_fails(self):
        self._publish(root=b"\xff" * 32)
        with self.assertRaisesRegex(ValueError, "does not verify"):
            verify_published(self.temp_dir, self.digests[0], self.EPOCH)

    def test_an_attestation_for_another_epoch_fails(self):
        self._publish(attestation_epoch=self.EPOCH + 1)
        with self.assertRaisesRegex(ValueError, "is for epoch 8"):
            verify_published(self.temp_dir, self.digests[0], self.EPOCH)

    def test_an_unpublished_epoch_is_not_found(self):
        with self.assertRaises(FileNotFoundError):
            verify_published(self.temp_dir, self.digests[0], self.EPOCH)


if __name__ == "__main__":
    unittest.main()
