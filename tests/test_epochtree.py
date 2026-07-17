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
    decode_leaf_set,
    encode_leaf_set,
    verify_inclusion,
    verify_non_inclusion,
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
    return ZeitwerkPendingAttestation(epoch, "https://recover.zeitwerk.example")


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
        # Upstream make_merkle_tree returns the lone stamp unhashed. The
        # stamper must therefore never sign a bare root (Stage 5).
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


class LeafSetTests(unittest.TestCase):
    def test_encode_decode_round_trips(self):
        tree = build_epoch_tree(_digests(5))
        self.assertEqual(decode_leaf_set(encode_leaf_set(tree.leaves)), tree.leaves)

    def test_encode_rejects_non_canonical_order(self):
        ds = _digests(3)
        with self.assertRaises(ValueError):
            encode_leaf_set(tuple(reversed(sorted(ds))))

    def test_decode_rejects_truncated_buffer(self):
        buf = encode_leaf_set(build_epoch_tree(_digests(3)).leaves)
        with self.assertRaises(ValueError):
            decode_leaf_set(buf[:-1])

    def test_decode_rejects_unsorted(self):
        a, b = sorted(_digests(2))
        with self.assertRaises(ValueError):
            decode_leaf_set(b + a)

    def test_decode_rejects_duplicates(self):
        (a,) = _digests(1)
        with self.assertRaises(ValueError):
            decode_leaf_set(a + a)

    def test_decode_rejects_empty(self):
        with self.assertRaises(ValueError):
            decode_leaf_set(b"")

    def test_decode_rejects_non_bytes(self):
        with self.assertRaises(TypeError):
            decode_leaf_set("00" * 32)


class StrictVerificationTests(unittest.TestCase):
    def setUp(self):
        self.ds = _digests(8)
        self.tree = build_epoch_tree(self.ds)
        self.buf = encode_leaf_set(self.tree.leaves)
        self.absent = hashlib.sha256(b"absent").digest()

    def test_present_digest_is_included(self):
        self.assertTrue(verify_inclusion(self.ds[0], self.buf, self.tree.root))
        self.assertFalse(verify_non_inclusion(self.ds[0], self.buf, self.tree.root))

    def test_absent_digest_is_non_included(self):
        self.assertFalse(verify_inclusion(self.absent, self.buf, self.tree.root))
        self.assertTrue(verify_non_inclusion(self.absent, self.buf, self.tree.root))

    def test_set_not_matching_root_fails_both_ways(self):
        wrong = hashlib.sha256(b"wrong root").digest()
        self.assertFalse(verify_inclusion(self.ds[0], self.buf, wrong))
        self.assertFalse(verify_non_inclusion(self.absent, self.buf, wrong))

    def test_tampered_set_fails_both_ways(self):
        # Swap one leaf for another valid-looking digest, keep canonical order.
        leaves = sorted([*self.tree.leaves[:-1], self.absent])
        buf = encode_leaf_set(tuple(leaves))
        self.assertFalse(verify_inclusion(self.ds[0], buf, self.tree.root))
        self.assertFalse(verify_non_inclusion(self.absent, buf, self.tree.root))

    def test_chain_extension_attack_passes_existence_fails_inclusion(self):
        """The module docstring's fine print, as a test.

        Fingerprints are submitter-chosen: submit X = SHA256(L' + junk) and
        you can later exhibit a genuine receipt for L' although L' is not
        on the list. The receipt honestly proves L' existed before the root
        — but inclusion means list membership, and only list membership.
        """
        l_prime = hashlib.sha256(b"the attacker's real document").digest()
        junk = b"\xaa" * 32
        x = hashlib.sha256(l_prime + junk).digest()

        tree = build_epoch_tree([x, *self.ds])
        tree.tip.attestations.add(_tip_attestation())
        buf = encode_leaf_set(tree.leaves)

        # Extension chain: L' -> append junk -> sha256 -> X, then X's chain.
        chain = Timestamp(l_prime)
        chain.ops.add(OpAppend(junk)).ops.add(OpSHA256()).merge(tree.proof(x))
        ctx = BytesSerializationContext()
        chain.serialize(ctx)
        receipt = ctx.getbytes()

        self.assertTrue(verify_receipt(l_prime, receipt, tree.root))
        self.assertFalse(verify_inclusion(l_prime, buf, tree.root))
        self.assertTrue(verify_non_inclusion(l_prime, buf, tree.root))


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
        # attestation to UnknownAttestation (it keeps the tag) — so finding
        # our tag at the root msg proves the whole chain checked out.
        [(msg, attestation)] = parsed.all_attestations()
        self.assertEqual(msg, tree.root)
        self.assertEqual(attestation.TAG, _tip_attestation().TAG)


if __name__ == "__main__":
    unittest.main()
