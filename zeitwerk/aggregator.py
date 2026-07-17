"""Epoch lifecycle: collect fingerprints, close, seal, issue receipts.
The life of an epoch, in order:

    agg = Aggregator(epoch=7)
    agg.submit(digest)            # repeat for everyone
    closed = agg.close()          # list frozen, tree built
    publish(closed.leaf_set)      # the public artifact
    closed.seal(attestation)      # once — the anchor's signature
    closed.receipt(digest)        # receipt bytes for each submitter
"""

from __future__ import annotations

from zeitwerk.epochtree import (
    MAX_LEAVES,
    EpochTree,
    build_epoch_tree,
    check_digest,
    encode_leaf_set,
)


class ClosedEpoch:
    """A closed epoch: publish `leaf_set`, `seal()` once, then `receipt()`."""

    def __init__(self, epoch: int, tree: EpochTree | None):
        self.epoch = epoch
        self._tree = tree
        self._sealed = False

    @property
    def root(self):
        """The epoch root, or None if nothing was submitted."""
        return self._tree.root if self._tree else None

    @property
    def leaf_set(self):
        """The publishable byte string, or None if nothing was submitted."""
        return encode_leaf_set(self._tree.leaves) if self._tree else None

    def seal(self, *attestations) -> None:
        """Attach the epoch's attestation(s) — the anchor over the root.
        Exactly once; before this, no receipts."""
        if self._tree is None:
            raise RuntimeError(f"epoch {self.epoch} is empty — nothing to seal")
        if self._sealed:
            raise RuntimeError(
                f"epoch {self.epoch} is already sealed — sealing again "
                f"would silently change every receipt"
            )
        if not attestations:
            raise ValueError("seal needs at least one attestation (the epoch's anchor)")
        self._tree.tip.attestations.update(attestations)
        self._sealed = True

    def receipt(self, digest: bytes) -> bytes:
        """The submitter's receipt, as bytes ready to store or send."""
        if not self._sealed:
            raise RuntimeError(
                f"seal epoch {self.epoch} with its anchor attestation "
                f"before issuing receipts"
            )
        return self._tree.receipt_bytes(digest)


class Aggregator:
    """Collects an epoch's fingerprints; close() freezes them into a tree.

    Duplicate submissions of one fingerprint collapse to one leaf; every
    submitter of that fingerprint gets the identical receipt.
    """

    def __init__(self, epoch: int, max_leaves: int = MAX_LEAVES):
        if not isinstance(epoch, int) or epoch < 0:
            raise ValueError(f"epoch must be a non-negative int, got {epoch!r}")
        if not 0 < max_leaves <= MAX_LEAVES:
            raise ValueError(f"max_leaves must be in 1..{MAX_LEAVES}, got {max_leaves}")
        self.epoch = epoch
        self.max_leaves = max_leaves
        self._digests = set()
        self._closed = False

    def submit(self, digest: bytes) -> None:
        """Add a fingerprint to the epoch. Rejects, never truncates, when full."""
        if self._closed:
            raise RuntimeError(f"epoch {self.epoch} is closed")
        check_digest(digest)
        if len(self._digests) >= self.max_leaves and digest not in self._digests:
            raise ValueError(f"epoch {self.epoch} is full ({self.max_leaves} leaves)")
        self._digests.add(digest)

    def close(self) -> ClosedEpoch:
        """Freeze the epoch and build its tree; no further submissions."""
        if self._closed:
            raise RuntimeError(f"epoch {self.epoch} is already closed")
        self._closed = True
        tree = build_epoch_tree(self._digests) if self._digests else None
        return ClosedEpoch(self.epoch, tree)
