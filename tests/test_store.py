"""Tests for the SQLite store."""

import tempfile
import unittest
from pathlib import Path

from zeitwerk.store import Store, EpochClosed, EpochFull
from zeitwerk.epochtree import MAX_LEAVES

DIGEST = b"\x01" * 32
DIGEST2 = b"\x02" * 32
EPOCH = 7
EPOCH2 = 8


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


class StoreSubmissionTests(unittest.TestCase):
    def setUp(self):
        self.store = Store(":memory:")
        self.addCleanup(self.store.close)

    def test_add_submission_records_the_digest(self):
        self.store.add_submission(DIGEST, EPOCH)
        self.assertTrue(self.store.is_submitted(DIGEST))

    def test_add_submission_same_digest_same_epoch_is_noop(self):
        self.store.add_submission(DIGEST, EPOCH)
        self.store.add_submission(DIGEST, EPOCH)  # no error, no duplicate
        # Should still be visible
        self.assertTrue(self.store.is_submitted(DIGEST))

    def test_add_submission_same_digest_different_epoch_stores_twice(self):
        self.store.add_submission(DIGEST, EPOCH)
        self.store.add_submission(DIGEST, EPOCH2)
        self.assertEqual(self.store.close_epoch(EPOCH), DIGEST)
        self.assertEqual(self.store.close_epoch(EPOCH2), DIGEST)

    def test_is_submitted_returns_false_for_unknown_digest(self):
        self.assertFalse(self.store.is_submitted(DIGEST))

    def test_is_submitted_returns_true_after_add(self):
        self.store.add_submission(DIGEST, EPOCH)
        self.assertTrue(self.store.is_submitted(DIGEST))

    def test_submission_persists_across_reopen(self):
        """Core test: a restart loses nothing."""
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / "zeitwerk.db"
        
        # Submit to first store instance
        store1 = Store(path)
        store1.add_submission(DIGEST, EPOCH)
        store1.close()
        
        # Reopen and check
        store2 = Store(path)
        self.addCleanup(store2.close)
        self.assertTrue(store2.is_submitted(DIGEST))

    def test_add_submission_to_closed_epoch_raises(self):
        self.store.add_submission(DIGEST, EPOCH)
        self.store.close_epoch(EPOCH)
        with self.assertRaises(EpochClosed):
            self.store.add_submission(DIGEST2, EPOCH)

    def test_add_submission_to_full_epoch_raises(self):
        """An epoch at max_leaves unique digests refuses new ones."""
        # Create a store with a small limit for testing
        small_limit = 3
        store = Store(":memory:", max_leaves=small_limit)
        self.addCleanup(store.close)
        
        # Fill the epoch to the limit with unique digests
        # Use distinct bytes that won't accidentally match DIGEST
        for i in range(small_limit):
            store.add_submission(bytes([i + 10]) * 32, EPOCH)
        
        # Next unique digest should fail
        with self.assertRaises(EpochFull):
            store.add_submission(DIGEST, EPOCH)
        
        # But re-submitting an existing digest should still be a no-op
        store.add_submission(bytes([10]) * 32, EPOCH)  # Already exists, no error

    def test_add_submission_respects_default_max_leaves(self):
        """Store with default max_leaves works normally."""
        # Add a few unique digests (well below MAX_LEAVES)
        for i in range(10):
            self.store.add_submission(bytes([i]) * 32, EPOCH)
        
        # Verify all are there
        for i in range(10):
            self.assertTrue(self.store.is_submitted(bytes([i]) * 32))


class StoreEpochTests(unittest.TestCase):
    def setUp(self):
        self.store = Store(":memory:")
        self.addCleanup(self.store.close)

    def test_close_epoch_returns_leaf_set(self):
        self.store.add_submission(DIGEST, EPOCH)
        leaf_set = self.store.close_epoch(EPOCH)
        self.assertEqual(leaf_set, DIGEST)

    def test_close_epoch_empty_epoch(self):
        leaf_set = self.store.close_epoch(EPOCH)
        self.assertEqual(leaf_set, b"")

    def test_close_epoch_twice_returns_same_leaf_set(self):
        self.store.add_submission(DIGEST, EPOCH)
        leaf_set1 = self.store.close_epoch(EPOCH)
        leaf_set2 = self.store.close_epoch(EPOCH)
        self.assertEqual(leaf_set1, leaf_set2)

    def test_close_epoch_multiple_digests_sorted(self):
        self.store.add_submission(DIGEST2, EPOCH)
        self.store.add_submission(DIGEST, EPOCH)
        leaf_set = self.store.close_epoch(EPOCH)
        # Should be sorted: DIGEST < DIGEST2
        self.assertEqual(leaf_set, DIGEST + DIGEST2)

    def test_close_epoch_deduplicates(self):
        self.store.add_submission(DIGEST, EPOCH)
        self.store.add_submission(DIGEST, EPOCH)  # duplicate
        leaf_set = self.store.close_epoch(EPOCH)
        self.assertEqual(leaf_set, DIGEST)  # Only one copy

    def test_seal_epoch_twice_raises(self):
        self.store.add_submission(DIGEST, EPOCH)
        self.store.close_epoch(EPOCH)
        self.store.seal_epoch(EPOCH, b"\x03" * 32, b"attestation bytes")
        with self.assertRaises(ValueError):
            self.store.seal_epoch(EPOCH, b"\x04" * 32, b"other bytes")

    def test_seal_epoch_requires_closed_epoch(self):
        with self.assertRaises(ValueError):
            self.store.seal_epoch(EPOCH, b"\x03" * 32, b"")

    def test_seal_epoch_requires_valid_root_length(self):
        self.store.close_epoch(EPOCH)
        with self.assertRaises(ValueError):
            self.store.seal_epoch(EPOCH, b"\x03" * 31, b"")


def _seal(store, epoch):
    """Close and seal an hour with a dummy root; return its attestation bytes."""
    attestation = b"attestation for %d" % epoch
    store.close_epoch(epoch)
    store.seal_epoch(epoch, b"\x03" * 32, attestation)
    return attestation


class StoreUnsealedEpochsTests(unittest.TestCase):
    def setUp(self):
        self.store = Store(":memory:")
        self.addCleanup(self.store.close)

    def test_empty_store_has_nothing_to_seal(self):
        self.assertEqual(self.store.unsealed_epochs(before=EPOCH2), [])

    def test_lists_past_hours_with_submissions_oldest_first(self):
        self.store.add_submission(DIGEST, EPOCH2)
        self.store.add_submission(DIGEST, EPOCH)
        self.assertEqual(self.store.unsealed_epochs(before=EPOCH2 + 1), [EPOCH, EPOCH2])

    def test_leaves_out_the_current_hour(self):
        self.store.add_submission(DIGEST, EPOCH)
        self.store.add_submission(DIGEST, EPOCH2)
        self.assertEqual(self.store.unsealed_epochs(before=EPOCH2), [EPOCH])

    def test_lists_an_hour_once_whatever_its_submissions(self):
        self.store.add_submission(DIGEST, EPOCH)
        self.store.add_submission(DIGEST2, EPOCH)
        self.assertEqual(self.store.unsealed_epochs(before=EPOCH2), [EPOCH])

    def test_leaves_out_sealed_hours(self):
        self.store.add_submission(DIGEST, EPOCH)
        self.store.add_submission(DIGEST, EPOCH2)
        _seal(self.store, EPOCH)
        self.assertEqual(self.store.unsealed_epochs(before=EPOCH2 + 1), [EPOCH2])

    def test_keeps_an_hour_closed_but_never_sealed(self):
        """A crash between close and seal: the closer must pick it back up."""
        self.store.add_submission(DIGEST, EPOCH)
        self.store.close_epoch(EPOCH)
        self.assertEqual(self.store.unsealed_epochs(before=EPOCH2), [EPOCH])

    def test_leaves_out_a_closed_empty_hour(self):
        self.store.close_epoch(EPOCH)
        self.assertEqual(self.store.unsealed_epochs(before=EPOCH2), [])


class StoreSealedForTests(unittest.TestCase):
    def setUp(self):
        self.store = Store(":memory:")
        self.addCleanup(self.store.close)

    def test_unknown_digest_is_none(self):
        self.assertIsNone(self.store.sealed_for(DIGEST))

    def test_pending_digest_is_none(self):
        self.store.add_submission(DIGEST, EPOCH)
        self.assertIsNone(self.store.sealed_for(DIGEST))

    def test_closed_but_unsealed_is_none(self):
        self.store.add_submission(DIGEST, EPOCH)
        self.store.close_epoch(EPOCH)
        self.assertIsNone(self.store.sealed_for(DIGEST))

    def test_sealed_digest_gets_leaf_set_and_attestation(self):
        self.store.add_submission(DIGEST2, EPOCH)
        self.store.add_submission(DIGEST, EPOCH)
        attestation = _seal(self.store, EPOCH)
        self.assertEqual(self.store.sealed_for(DIGEST), (DIGEST + DIGEST2, attestation))

    def test_digest_in_two_sealed_hours_gets_the_earliest(self):
        self.store.add_submission(DIGEST, EPOCH2)
        self.store.add_submission(DIGEST, EPOCH)
        attestation = _seal(self.store, EPOCH)
        _seal(self.store, EPOCH2)
        self.assertEqual(self.store.sealed_for(DIGEST), (DIGEST, attestation))

    def test_skips_an_earlier_hour_not_yet_sealed(self):
        self.store.add_submission(DIGEST, EPOCH)
        self.store.add_submission(DIGEST, EPOCH2)
        self.store.close_epoch(EPOCH)
        attestation = _seal(self.store, EPOCH2)
        self.assertEqual(self.store.sealed_for(DIGEST), (DIGEST, attestation))

    def test_rejects_a_bad_digest(self):
        with self.assertRaises(ValueError):
            self.store.sealed_for(b"\x01" * 31)


if __name__ == "__main__":
    unittest.main()
