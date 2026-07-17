"""Tests for the per-epoch Merkle tree.

Runs with the stdlib: `python3 -m unittest discover tests`.
"""

import hashlib
import random
import unittest
from pathlib import Path

import zeitwerk  # noqa: F401  (runs the python-opentimestamps path shim)
from zeitwerk.attestation import ZeitwerkPendingAttestation
from zeitwerk.epochtree import (
    MAX_PROOF_LEVELS,
    build_epoch_tree,
    verify_receipt,
)

from opentimestamps.core.op import OpAppend, OpSHA1, OpSHA256
from opentimestamps.core.serialize import (
    BytesDeserializationContext,
    BytesSerializationContext,
)
from opentimestamps.core.timestamp import Timestamp

FIXTURES = Path(__file__).parent.parent / "fixtures"


def _digests(n):
    return [hashlib.sha256(i.to_bytes(4, "big")).digest() for i in range(n)]


def _tip_attestation(epoch=1):
    return ZeitwerkPendingAttestation(epoch, "https://recover.zeitwerk.example") # stub URL


def _serialized_proof(tree, digest):
    ctx = BytesSerializationContext()
    tree.proof(digest).serialize(ctx)
    return ctx.getbytes()


class TreeBuildTests(unittest.TestCase):
    def test_leaves_are_deduplicated_and_sorted(self):
        ds = _digests(8)
        tree = build_epoch_tree([ds[3], *reversed(ds)])
        self.assertEqual(tree.leaves, tuple(sorted(ds)))

    def test_root_deterministic_across_input_orders(self):
        ds = _digests(8)
        orders = [ds, list(reversed(ds)), random.Random(0).sample(ds, len(ds))]
        roots = {build_epoch_tree(order).root for order in orders}
        self.assertEqual(len(roots), 1)

    def test_proofs_byte_identical_across_input_orders(self):
        ds = _digests(8)
        a = build_epoch_tree(ds)
        b = build_epoch_tree(list(reversed(ds)))
        a.tip.attestations.add(_tip_attestation())
        b.tip.attestations.add(_tip_attestation())
        for d in ds:
            self.assertEqual(_serialized_proof(a, d), _serialized_proof(b, d))

    def test_every_leaf_gets_a_proof(self):
        for n in (1, 2, 3, 5, 8, 257):
            tree = build_epoch_tree(_digests(n))
            for d in _digests(n):
                self.assertEqual(tree.proof(d).msg, d)

    def test_single_leaf_root_is_the_leaf(self):
        (d,) = _digests(1)
        self.assertEqual(build_epoch_tree([d]).root, d)

    def test_empty_raises(self):
        with self.assertRaises(ValueError):
            build_epoch_tree([])

    def test_rejects_wrong_length_digest(self):
        with self.assertRaises(ValueError):
            build_epoch_tree([b"short"])

    def test_rejects_str_digest(self):
        with self.assertRaises(TypeError):
            build_epoch_tree(["a" * 32])

    def test_proof_for_unknown_digest_raises(self):
        tree = build_epoch_tree(_digests(4))
        with self.assertRaises(ValueError):
            tree.proof(hashlib.sha256(b"absent").digest())

    def test_proofmode_fixture_digest_gets_a_proof(self):
        ots = next((FIXTURES / "proofmode-pending").glob("*.ots"))
        digest = bytes.fromhex(ots.stem)  # fixture files are named by digest
        tree = build_epoch_tree([digest, *_digests(4)])
        self.assertEqual(tree.proof(digest).msg, digest)

    def test_second_tip_attestation_changes_every_proof(self):
        # All proofs alias one tip: attach epoch-wide attestations exactly
        # once. This is why ClosedEpoch.seal() refuses to run twice.
        ds = _digests(5)
        tree = build_epoch_tree(ds)
        tree.tip.attestations.add(_tip_attestation(epoch=1))
        before = [_serialized_proof(tree, d) for d in ds]
        tree.tip.attestations.add(_tip_attestation(epoch=2))
        after = [_serialized_proof(tree, d) for d in ds]
        for x, y in zip(before, after):
            self.assertNotEqual(x, y)


class ReceiptTests(unittest.TestCase):
    def test_every_leaf_receipt_verifies(self):
        for n in (1, 2, 3, 5, 8, 257):
            tree = build_epoch_tree(_digests(n))
            tree.tip.attestations.add(_tip_attestation())
            for d in _digests(n):
                self.assertTrue(verify_receipt(d, tree.receipt_bytes(d), tree.root))

    def test_wrong_root_fails(self):
        ds = _digests(4)
        tree = build_epoch_tree(ds)
        tree.tip.attestations.add(_tip_attestation())
        self.assertFalse(verify_receipt(ds[0], tree.receipt_bytes(ds[0]), ds[1]))

    def test_wrong_digest_fails(self):
        ds = _digests(4)
        tree = build_epoch_tree(ds)
        tree.tip.attestations.add(_tip_attestation())
        self.assertFalse(verify_receipt(ds[1], tree.receipt_bytes(ds[0]), tree.root))

    def test_garbage_bytes_fail_without_raising(self):
        (d,) = _digests(1)
        self.assertFalse(verify_receipt(d, b"\x00not a receipt", d))

    def test_truncated_receipt_fails_without_raising(self):
        tree = build_epoch_tree(_digests(4))
        tree.tip.attestations.add(_tip_attestation())
        wire = tree.receipt_bytes(_digests(4)[0])
        self.assertFalse(verify_receipt(_digests(4)[0], wire[:-3], tree.root))

    def test_non_bytes_receipt_raises(self):
        (d,) = _digests(1)
        with self.assertRaises(TypeError):
            verify_receipt(d, "not bytes", d)

    def _receipt(self, start, tip):
        """Serialize a hand-built chain, attesting its tip first."""
        tip.attestations.add(_tip_attestation())
        ctx = BytesSerializationContext()
        start.serialize(ctx)
        return ctx.getbytes()

    def _chain(self, digest, levels, sibling=b"\x00" * 32):
        """A canonical chain; returns (start stamp, tip stamp)."""
        start = Timestamp(digest)
        stamp = start
        for _ in range(levels):
            stamp = stamp.ops.add(OpAppend(sibling)).ops.add(OpSHA256())
        return start, stamp

    def test_zero_ops_only_when_digest_is_root(self):
        (d,) = _digests(1)
        start, tip = self._chain(d, 0)
        wire = self._receipt(start, tip)
        other = hashlib.sha256(b"other").digest()
        self.assertTrue(verify_receipt(d, wire, d))  # single-leaf epoch
        self.assertFalse(verify_receipt(d, wire, other))

    def test_deepest_plausible_chain_passes(self):
        (d,) = _digests(1)
        start, tip = self._chain(d, MAX_PROOF_LEVELS)
        self.assertTrue(verify_receipt(d, self._receipt(start, tip), tip.msg))

    def test_over_deep_chain_fails(self):
        (d,) = _digests(1)
        start, tip = self._chain(d, MAX_PROOF_LEVELS + 1)
        self.assertFalse(verify_receipt(d, self._receipt(start, tip), tip.msg))

    def test_sha1_link_fails(self):
        (d,) = _digests(1)
        start = Timestamp(d)
        tip = start.ops.add(OpAppend(b"\x00" * 32)).ops.add(OpSHA1())
        root = tip.msg + b"\x00" * 12  # pad SHA-1 up to 32 bytes
        self.assertFalse(verify_receipt(d, self._receipt(start, tip), root))

    def test_missing_binop_fails(self):
        # digest -> sha256 -> root, no sibling: never produced by the tree.
        (d,) = _digests(1)
        start = Timestamp(d)
        tip = start.ops.add(OpSHA256())
        self.assertFalse(verify_receipt(d, self._receipt(start, tip), tip.msg))

    def test_oversized_sibling_fails(self):
        (d,) = _digests(1)
        start, tip = self._chain(d, 1, sibling=b"\x00" * 64)
        self.assertFalse(verify_receipt(d, self._receipt(start, tip), tip.msg))

    def test_branching_receipt_fails(self):
        (d,) = _digests(1)
        start, tip = self._chain(d, 1)
        branch = start.ops.add(OpAppend(b"\x11" * 32))  # second branch
        branch.attestations.add(_tip_attestation())
        self.assertFalse(verify_receipt(d, self._receipt(start, tip), tip.msg))


class StockOtsInteropTests(unittest.TestCase):
    def test_stock_ots_recomputes_the_root_from_a_serialized_proof(self):
        """A proof round-trips through stock OTS code (no zeitwerk imports in
        the verify path) and recomputes to the epoch root."""
        ds = _digests(5)
        tree = build_epoch_tree(ds)
        tree.tip.attestations.add(_tip_attestation())

        wire = _serialized_proof(tree, ds[2])
        parsed = Timestamp.deserialize(BytesDeserializationContext(wire), ds[2])

        # Stock OTS recomputes every message while parsing, and degrades our
        # attestation to UnknownAttestation — so finding our tag
        # at the root msg proves the whole chain checked out.
        [(msg, attestation)] = parsed.all_attestations()
        self.assertEqual(msg, tree.root)
        self.assertEqual(attestation.TAG, _tip_attestation().TAG)


if __name__ == "__main__":
    unittest.main()
