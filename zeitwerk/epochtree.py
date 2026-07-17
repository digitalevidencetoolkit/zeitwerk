"""One epoch's public record: a sorted list of fingerprints and its root.

In plain words: during an epoch, people submit 32-byte fingerprints
(SHA-256 hashes) of their documents. At the close, the fingerprints are
sorted into one list, and the list is hash-paired down to a single
32-byte value — the epoch root (a Merkle tree, built by the stock
OpenTimestamps library, so ordinary OTS tools can read our receipts).
The root gets anchored (signed); the full list gets published.

Because the same list always rebuilds the same tree, a lost receipt can
be reconstructed, byte for byte, from a fingerprint plus the published
list. Nobody has to keep anything.

The fine print (it matters for disputes): fingerprints are
submitter-chosen, so a genuine receipt can exist for a fingerprint that
is *not* on the published list. A receipt proves the fingerprint existed
before the root was anchored — which is all classic OpenTimestamps ever
proves. "In epoch N" means: on the published list. Checks that decide
anything — recovery, disputes, audits — use the list.
"""

from __future__ import annotations

from opentimestamps.core.timestamp import Timestamp, make_merkle_tree

DIGEST_SIZE = 32
MAX_LEAVES = 2**20  # bounds epoch memory and leaf-set decode (~33 MiB encoded)


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
    """A built epoch tree: canonical `leaves`, their `root`, one shared tip.

    This is a building block — receipt bytes come from higher up (a sealed
    epoch, or recovery from the published list). Every leaf's proof runs
    through the one shared `tip` object, so whatever is attached there
    appears in every receipt: epoch-wide attestations only, attached once.
    """

    def __init__(self, root: bytes, leaves: tuple, stamps: dict, tip: Timestamp):
        self.root = root
        self.leaves = leaves
        self.tip = tip
        self._stamps = stamps

    def proof(self, digest: bytes) -> Timestamp:
        """The fingerprint's leaf Timestamp — a live view into the shared
        tree, for building and testing; receipts hand out bytes instead."""
        check_digest(digest)
        try:
            return self._stamps[digest]
        except KeyError:
            raise ValueError(
                f"fingerprint is not in this epoch: {digest.hex()}"
            ) from None


def build_epoch_tree(digests) -> EpochTree:
    """Sort the fingerprints into their canonical order, then merkle.

    Deterministic: any input order of the same fingerprints yields the same
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
