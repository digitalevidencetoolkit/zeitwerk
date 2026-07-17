"""One epoch's public record: a sorted list of fingerprints and its root.

In plain English, hopefully: during an epoch, people submit 32-byte fingerprints
(SHA-256 hashes) of their documents. At the epoch's close, the fingerprints are
sorted into one list, and the list is hash-paired down to a single
32-byte value: the epoch root. The root gets anchored (signed); the full list gets published.

Because the same list always rebuilds the same tree, a lost receipt can
be reconstructed from a fingerprint plus the published list. Nobody has to keep anything.

"In epoch N" means: on the published list. Checks that decide anything — recovery,
disputes, audits — use the list.
"""

from __future__ import annotations

from opentimestamps.core.op import OpAppend, OpPrepend, OpSHA256
from opentimestamps.core.serialize import (
    BytesDeserializationContext,
    BytesSerializationContext,
    DeserializationError,
)
from opentimestamps.core.timestamp import Timestamp, make_merkle_tree

DIGEST_SIZE = 32
MAX_LEAVES = 2**20  # bounds epoch memory and leaf-set decode (~33 MiB encoded)

# An epoch of <= MAX_LEAVES leaves never merkles deeper than this.
MAX_PROOF_LEVELS = MAX_LEAVES.bit_length()  # 21


def check_digest(digest: bytes) -> None:
    """Reject anything that isn't a 32-byte fingerprint."""
    if isinstance(digest, str):
        raise TypeError(
            "digest must be raw bytes, not str — use bytes.fromhex() for a "
            "hex string, or hashlib.sha256(data).digest() for content"
        )
    if not isinstance(digest, bytes):
        raise TypeError(f"digest must be bytes, got {type(digest).__name__}")
    if len(digest) != DIGEST_SIZE:
        raise ValueError(
            f"digest must be exactly {DIGEST_SIZE} bytes "
            f"(a SHA-256 fingerprint), got {len(digest)} bytes"
        )


class EpochTree:
    """A built epoch tree: canonical `leaves`, their `root`, and one shared tip.
    """

    def __init__(self, root: bytes, leaves: tuple, stamps: dict, tip: Timestamp):
        self.root = root
        self.leaves = leaves
        self.tip = tip
        self._stamps = stamps

    def proof(self, digest: bytes) -> Timestamp:
        check_digest(digest)
        try:
            return self._stamps[digest]
        except KeyError:
            raise ValueError(
                f"fingerprint is not in this epoch: {digest.hex()}"
            ) from None

    def receipt_bytes(self, digest: bytes) -> bytes:
        """The fingerprint's receipt serialized to OTS.

        The tip must already carry the epoch's attestation(s) — a receipt
        ends in an attestation, and the OTS format refuses to serialize one
        that doesn't.
        """
        ctx = BytesSerializationContext()
        self.proof(digest).serialize(ctx)
        return ctx.getbytes()


def build_epoch_tree(digests) -> EpochTree:
    """Sort the fingerprints into their canonical order, then merkle.

    Objective: Deterministim. Any input order of the same fingerprints yields the same
    root and byte-identical proofs (for a fixed tip attestation set).
    Recovery from the published list is exactly this function.
    """
    digests = list(digests)
    for digest in digests:
        check_digest(digest)
    leaves = tuple(sorted(set(digests)))
    if not leaves:
        raise ValueError("cannot build a tree from an empty epoch")

    stamps = {leaf: Timestamp(leaf) for leaf in leaves}
    tip = make_merkle_tree([stamps[leaf] for leaf in leaves])
    return EpochTree(tip.msg, leaves, stamps, tip)


def encode_leaf_set(leaves) -> bytes:
    """The publishable form of an epoch: its sorted fingerprints, joined. """
    buf = b"".join(leaves)
    decoded = decode_leaf_set(buf)
    if decoded != tuple(leaves):
        raise ValueError("leaves are not in canonical form (sorted, no duplicates)")
    return buf


def decode_leaf_set(buf: bytes) -> tuple:
    """Parse a published leaf set; canonical form or nothing."""
    if not isinstance(buf, bytes):
        raise TypeError(f"leaf set must be bytes, got {type(buf).__name__}")
    if len(buf) > MAX_LEAVES * DIGEST_SIZE:
        raise ValueError(f"leaf set too large: {len(buf)} bytes")
    if len(buf) % DIGEST_SIZE != 0:
        raise ValueError(
            f"leaf set must be a whole number of {DIGEST_SIZE}-byte "
            f"fingerprints, got {len(buf)} bytes"
        )
    leaves = tuple(buf[i : i + DIGEST_SIZE] for i in range(0, len(buf), DIGEST_SIZE))
    if not leaves:
        raise ValueError("leaf set is empty")
    for a, b in zip(leaves, leaves[1:]):
        if a >= b:  # catches both unsorted and duplicates
            raise ValueError("leaf set is not in canonical order (sorted, no duplicates)")
    return leaves


def verify_inclusion(digest: bytes, leaf_set_buf: bytes, root: bytes) -> bool:
    """Is this fingerprint on the epoch's published list?

    True iff the list is canonical, recomputes to `root`, and contains
    `digest`. This — not a receipt — is what "timestamped in epoch N"
    means.
    """
    check_digest(digest)
    check_digest(root)
    leaves = decode_leaf_set(leaf_set_buf)
    if build_epoch_tree(leaves).root != root:
        return False
    return digest in set(leaves)


def verify_non_inclusion(digest: bytes, leaf_set_buf: bytes, root: bytes) -> bool:
    """Is this fingerprint certainly NOT on the epoch's published list?"""
    check_digest(digest)
    check_digest(root)
    leaves = decode_leaf_set(leaf_set_buf)
    if build_epoch_tree(leaves).root != root:
        return False
    return digest not in set(leaves)


def recover_receipt(digest: bytes, leaf_set_buf: bytes, *attestations) -> bytes:
    """Lost the receipt? Rebuild it from the published list — byte for byte.

    Needs only the fingerprint, the epoch's published leaf set, and the
    epoch's attestation(s) (also published, alongside the list). This is
    the reason zeitwerk has no lose-your-receipt failure mode.
    """
    check_digest(digest)
    if not attestations:
        raise ValueError(
            "at least one attestation is needed — a receipt ends in the "
            "epoch's anchor, published next to the leaf set"
        )
    leaves = decode_leaf_set(leaf_set_buf)
    if digest not in set(leaves):
        raise ValueError(
            f"fingerprint is not on this epoch's published list: {digest.hex()}"
        )
    tree = build_epoch_tree(leaves)
    tree.tip.attestations.update(attestations)
    return tree.receipt_bytes(digest)


def verify_receipt(digest: bytes, receipt: bytes, root: bytes) -> bool:
    """I hold a receipt — is it genuine for this fingerprint and root?"""
    check_digest(digest)
    check_digest(root)
    if not isinstance(receipt, bytes):
        raise TypeError(f"receipt must be bytes, got {type(receipt).__name__}")
    try:
        ctx = BytesDeserializationContext(receipt)
        stamp = Timestamp.deserialize(ctx, digest)
        ctx.assert_eof()
    except DeserializationError:
        return False
    return _verify_chain(stamp, root)


def _single_op(stamp: Timestamp):
    """The node's only (op, child) — or (None, None) if it branches or ends."""
    if len(stamp.ops) != 1:
        return None, None
    return next(iter(stamp.ops.items()))


def _verify_chain(stamp: Timestamp, root: bytes) -> bool:
    """Walk a parsed receipt, holding it to the canonical proof shape."""
    for _ in range(MAX_PROOF_LEVELS + 1):
        if stamp.msg == root:
            return True
        op, child = _single_op(stamp)
        if type(op) not in (OpAppend, OpPrepend) or len(op[0]) != DIGEST_SIZE:
            return False
        op, stamp = _single_op(child)
        if type(op) is not OpSHA256:
            return False
    return False
