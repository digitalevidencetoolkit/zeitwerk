"""Tests for signed receipts: built by the witness, checked offline (issue #17)."""

import dataclasses
import hashlib
import unittest

import zeitwerk  # noqa: F401  (runs the python-opentimestamps path shim)
from zeitwerk.epochtree import build_epoch_tree, encode_leaf_set, recover_receipt
from zeitwerk.signer import Signer
from zeitwerk.witness import pending_receipt, signed_attestation, verify_signed_receipt

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

    def test_garbage_receipt_fails(self):
        self.assertFalse(verify_signed_receipt(self.digests[0], b"\xff" * 10, self.signer.public_key))


if __name__ == "__main__":
    unittest.main()
