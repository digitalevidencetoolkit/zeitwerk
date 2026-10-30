"""Tests for signed receipts: built by the witness, checked offline (issue #17)."""

import dataclasses
import hashlib
import unittest

import zeitwerk  # noqa: F401  (runs the python-opentimestamps path shim)
from zeitwerk.epochtree import build_epoch_tree, encode_leaf_set, recover_receipt
from zeitwerk.signer import Signer
from zeitwerk.store import Store
from zeitwerk.witness import (
    EPOCH_SECONDS,
    close_due,
    pending_receipt,
    signed_attestation,
    upgraded_receipt,
    verify_signed_receipt,
)

EPOCH = 7


def _digests(n):
    return [hashlib.sha256(i.to_bytes(4, "big")).digest() for i in range(n)]


def _signed_tree(signer, digests, epoch=EPOCH):
    tree = build_epoch_tree(digests)
    tree.tip.attestations.add(signed_attestation(signer, epoch, tree.root))
    return tree


class VerifySignedReceiptTests(unittest.TestCase):
    def setUp(self):
        self.signer = Signer()
        self.digests = _digests(3)

    def test_signed_receipt_verifies(self):
        tree = _signed_tree(self.signer, self.digests)
        receipt = tree.receipt_bytes(self.digests[0])
        self.assertTrue(verify_signed_receipt(self.digests[0], receipt, self.signer.public_key))

    def test_recovered_receipt_verifies(self):
        """Lose the receipt, rebuild it from the published list, and it still checks out."""
        tree = build_epoch_tree(self.digests)
        attestation = signed_attestation(self.signer, EPOCH, tree.root)
        receipt = recover_receipt(self.digests[0], encode_leaf_set(tree.leaves), attestation)
        self.assertTrue(verify_signed_receipt(self.digests[0], receipt, self.signer.public_key))

    def test_other_witness_key_fails(self):
        tree = _signed_tree(self.signer, self.digests)
        receipt = tree.receipt_bytes(self.digests[0])
        self.assertFalse(verify_signed_receipt(self.digests[0], receipt, Signer().public_key))

    def test_pending_receipt_fails(self):
        receipt = pending_receipt(self.digests[0], EPOCH, "https://recover.zeitwerk.example")
        self.assertFalse(verify_signed_receipt(self.digests[0], receipt, self.signer.public_key))

    def test_receipt_for_another_digest_fails(self):
        tree = _signed_tree(self.signer, self.digests)
        receipt = tree.receipt_bytes(self.digests[1])
        self.assertFalse(verify_signed_receipt(self.digests[0], receipt, self.signer.public_key))

    def test_moved_to_another_hour_fails(self):
        """The signature covers the epoch, so a receipt can't be moved to another hour."""
        tree = build_epoch_tree(self.digests)
        genuine = signed_attestation(self.signer, EPOCH, tree.root)
        tree.tip.attestations.add(dataclasses.replace(genuine, epoch=EPOCH + 1))
        receipt = tree.receipt_bytes(self.digests[0])
        self.assertFalse(verify_signed_receipt(self.digests[0], receipt, self.signer.public_key))

    def test_an_epoch_too_big_to_sign_fails(self):
        """A crafted epoch past 8 bytes reads as a bad receipt, rather than crashing."""
        tree = build_epoch_tree(self.digests)
        genuine = signed_attestation(self.signer, EPOCH, tree.root)
        tree.tip.attestations.add(dataclasses.replace(genuine, epoch=2**64))
        receipt = tree.receipt_bytes(self.digests[0])
        self.assertFalse(verify_signed_receipt(self.digests[0], receipt, self.signer.public_key))

    def test_garbage_receipt_fails(self):
        self.assertFalse(verify_signed_receipt(self.digests[0], b"\xff" * 10, self.signer.public_key))


def _hour(epoch):
    """The fake clock's time at the start of an epoch."""
    return epoch * EPOCH_SECONDS


class CloseDueTests(unittest.TestCase):
    def setUp(self):
        self.store = Store(":memory:")
        self.addCleanup(self.store.close)
        self.signer = Signer()
        self.digests = _digests(3)

    def _submit(self, epoch):
        for digest in self.digests:
            self.store.add_submission(digest, epoch)

    def test_nothing_to_seal_in_an_empty_store(self):
        self.assertEqual(close_due(self.store, self.signer, _hour(EPOCH)), [])

    def test_seals_a_finished_hour(self):
        self._submit(EPOCH)
        self.assertEqual(close_due(self.store, self.signer, _hour(EPOCH + 1)), [EPOCH])

    def test_leaves_the_current_hour_open(self):
        self._submit(EPOCH)
        self.assertEqual(close_due(self.store, self.signer, _hour(EPOCH + 1) - 1), [])

    def test_seals_several_hours_oldest_first(self):
        self._submit(EPOCH + 1)
        self._submit(EPOCH)
        self.assertEqual(close_due(self.store, self.signer, _hour(EPOCH + 2)), [EPOCH, EPOCH + 1])

    def test_a_second_call_has_nothing_left_to_seal(self):
        self._submit(EPOCH)
        close_due(self.store, self.signer, _hour(EPOCH + 1))
        self.assertEqual(close_due(self.store, self.signer, _hour(EPOCH + 1)), [])

    def test_picks_up_an_hour_closed_but_never_sealed(self):
        """A crash between close and seal: the next call carries on."""
        self._submit(EPOCH)
        self.store.close_epoch(EPOCH)
        self.assertEqual(close_due(self.store, self.signer, _hour(EPOCH + 1)), [EPOCH])


class UpgradedReceiptTests(unittest.TestCase):
    def setUp(self):
        self.store = Store(":memory:")
        self.addCleanup(self.store.close)
        self.signer = Signer()
        self.digests = _digests(3)
        for digest in self.digests:
            self.store.add_submission(digest, EPOCH)

    def test_unknown_digest_is_none(self):
        self.assertIsNone(upgraded_receipt(self.store, b"\xff" * 32))

    def test_pending_digest_is_none(self):
        self.assertIsNone(upgraded_receipt(self.store, self.digests[0]))

    def test_sealed_receipt_verifies_against_the_key(self):
        close_due(self.store, self.signer, _hour(EPOCH + 1))
        receipt = upgraded_receipt(self.store, self.digests[0])
        self.assertTrue(verify_signed_receipt(self.digests[0], receipt, self.signer.public_key))

    def test_same_bytes_as_rebuilt_from_the_published_list(self):
        """GET /timestamp, /recover and the published list all give one receipt.

        Ed25519 signatures are deterministic, so signing the root again here
        gives the very attestation the closer stored.
        """
        close_due(self.store, self.signer, _hour(EPOCH + 1))
        tree = build_epoch_tree(self.digests)
        attestation = signed_attestation(self.signer, EPOCH, tree.root)
        published = recover_receipt(self.digests[0], encode_leaf_set(tree.leaves), attestation)
        self.assertEqual(upgraded_receipt(self.store, self.digests[0]), published)


if __name__ == "__main__":
    unittest.main()
