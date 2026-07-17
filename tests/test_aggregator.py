"""Tests for the epoch aggregator lifecycle.

Runs with the stdlib: `python3 -m unittest discover tests`.
"""

import hashlib
import unittest

import zeitwerk  # noqa: F401  (runs the python-opentimestamps path shim)
from zeitwerk.aggregator import Aggregator
from zeitwerk.attestation import AnchorType, ZeitwerkAttestation
from zeitwerk.epochtree import (
    verify_inclusion,
    verify_non_inclusion,
    verify_receipt,
)


def _digests(n):
    return [hashlib.sha256(i.to_bytes(4, "big")).digest() for i in range(n)]


def _anchor(epoch=1):
    """A stand-in for the Stage 5 anchor attestation."""
    return ZeitwerkAttestation(epoch, AnchorType.FEDERATED_COSIGN, b"stub")


class AggregatorTests(unittest.TestCase):
    def test_duplicate_submissions_collapse_to_one_receipt(self):
        agg = Aggregator(epoch=1)
        (d,) = _digests(1)
        agg.submit(d)
        agg.submit(d)
        closed = agg.close()
        closed.seal(_anchor())
        self.assertEqual(closed.leaf_set, d)  # one leaf: the list is the leaf
        self.assertTrue(verify_receipt(d, closed.receipt(d), closed.root))

    def test_rejects_str_digest(self):
        with self.assertRaises(TypeError):
            Aggregator(epoch=1).submit("a" * 32)

    def test_rejects_wrong_length(self):
        with self.assertRaises(ValueError):
            Aggregator(epoch=1).submit(b"short")

    def test_rejects_submit_after_close(self):
        agg = Aggregator(epoch=1)
        agg.close()
        with self.assertRaises(RuntimeError):
            agg.submit(_digests(1)[0])

    def test_rejects_double_close(self):
        agg = Aggregator(epoch=1)
        agg.close()
        with self.assertRaises(RuntimeError):
            agg.close()

    def test_rejects_submit_when_full(self):
        agg = Aggregator(epoch=1, max_leaves=2)
        a, b, c = _digests(3)
        agg.submit(a)
        agg.submit(b)
        agg.submit(a)  # duplicate of an existing leaf still fine
        with self.assertRaises(ValueError):
            agg.submit(c)

    def test_rejects_bad_epoch_and_bounds(self):
        with self.assertRaises(ValueError):
            Aggregator(epoch=-1)
        with self.assertRaises(ValueError):
            Aggregator(epoch=1, max_leaves=0)


class ClosedEpochTests(unittest.TestCase):
    def _closed(self, n=5):
        agg = Aggregator(epoch=1)
        for d in _digests(n):
            agg.submit(d)
        return agg.close()

    def test_receipt_before_seal_raises(self):
        closed = self._closed()
        with self.assertRaises(RuntimeError):
            closed.receipt(_digests(1)[0])

    def test_seal_twice_raises(self):
        closed = self._closed()
        closed.seal(_anchor())
        with self.assertRaises(RuntimeError):
            closed.seal(_anchor(epoch=2))

    def test_seal_without_attestation_raises(self):
        with self.assertRaises(ValueError):
            self._closed().seal()

    def test_receipt_for_unknown_digest_raises(self):
        closed = self._closed()
        closed.seal(_anchor())
        with self.assertRaises(ValueError):
            closed.receipt(hashlib.sha256(b"absent").digest())

    def test_empty_epoch_has_no_tree_and_cannot_seal(self):
        closed = Aggregator(epoch=1).close()
        self.assertIsNone(closed.root)
        self.assertIsNone(closed.leaf_set)
        with self.assertRaises(RuntimeError):
            closed.seal(_anchor())

    def test_end_to_end(self):
        """Submit K fingerprints, close, publish, seal, then: every receipt
        verifies, every leaf is on the list, a non-member is not."""
        ds = _digests(7)
        agg = Aggregator(epoch=42)
        for d in ds:
            agg.submit(d)
        closed = agg.close()
        published = closed.leaf_set
        closed.seal(_anchor(epoch=42))

        self.assertEqual(closed.epoch, 42)
        for d in ds:
            self.assertTrue(verify_receipt(d, closed.receipt(d), closed.root))
            self.assertTrue(verify_inclusion(d, published, closed.root))
        absent = hashlib.sha256(b"never submitted").digest()
        self.assertTrue(verify_non_inclusion(absent, published, closed.root))


if __name__ == "__main__":
    unittest.main()
