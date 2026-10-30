"""The witness behind the HTTP routes (issue #17).

The pending receipt, the signed attestation the hourly close hangs on an
epoch's tip, the close itself, the upgraded receipt, and the offline check of
a signed receipt.
"""

from __future__ import annotations

from opentimestamps.core.serialize import (
    BytesDeserializationContext,
    BytesSerializationContext,
    DeserializationError,
)
from opentimestamps.core.timestamp import Timestamp

from zeitwerk.attestation import (
    AnchorType,
    ZeitwerkAttestation,
    ZeitwerkPendingAttestation,
    deserialize_attestation,
    serialize_attestation,
)
from zeitwerk.epochtree import build_epoch_tree, check_digest, decode_leaf_set, verify_receipt
from zeitwerk.signer import Signer, key_id_of
from zeitwerk.store import Store

EPOCH_SECONDS = 3600
KEY_ID_SIZE = 8
SIGNATURE_SIZE = 64


def pending_receipt(digest: bytes, epoch: int, recover_uri: str) -> bytes:
    """Just submitted? Here's your receipt, marked pending until the hour closes."""
    check_digest(digest)
    stamp = Timestamp(digest)
    stamp.attestations.add(ZeitwerkPendingAttestation(epoch, recover_uri))
    # Same three lines as EpochTree.receipt_bytes, fine to repeat for now.
    ctx = BytesSerializationContext()
    stamp.serialize(ctx)
    return ctx.getbytes()


def signed_attestation(signer: Signer, epoch: int, root: bytes) -> ZeitwerkAttestation:
    """What the hourly close hangs on the epoch's tip."""
    return ZeitwerkAttestation(
        epoch=epoch,
        anchor_type=AnchorType.WITNESS_ED25519,
        anchor_ref=signer.key_id + signer.sign(epoch, root),
    )


def close_due(store: Store, signer: Signer, now: float) -> list[int]:
    """Seal every finished hour that has submissions; return the epochs sealed.

    For each of store.unsealed_epochs(current epoch), oldest first:
    close_epoch freezes the leaf set, build_epoch_tree gives the root,
    signed_attestation signs it, and seal_epoch stores both. All state is in
    SQLite, so after a crash the next call just carries on.
    """
    current = int(now) // EPOCH_SECONDS
    sealed = []
    for epoch in store.unsealed_epochs(before=current):
        leaf_set = store.close_epoch(epoch)  # from here on, latecomers get EpochClosed
        tree = build_epoch_tree(decode_leaf_set(leaf_set))
        attestation = signed_attestation(signer, epoch, tree.root)
        store.seal_epoch(epoch, tree.root, serialize_attestation(attestation))
        sealed.append(epoch)
    return sealed


def upgraded_receipt(store: Store, digest: bytes) -> bytes | None:
    """The receipt for a sealed fingerprint, or None while pending or unknown.

    Rebuilt by recover_receipt from the leaf set and attestation, never
    stored: the bytes are the same ones /recover and the published list give.
    """
    raise NotImplementedError


def verify_signed_receipt(digest: bytes, receipt: bytes, pubkey: bytes) -> bool:
    """Verify a signed receipt offline with only the public key (issue #17).

    The root isn't stored in the attestation: it's the receipt node the
    attestation hangs on. The signature covers it, along with the epoch.
    """
    check_digest(digest)
    key_id = key_id_of(pubkey)
    try:
        stamp = Timestamp.deserialize(BytesDeserializationContext(receipt), digest)
    except DeserializationError:
        return False
    for root, unknown in stamp.all_attestations():
        try:  # stock OTS parses our tag as UnknownAttestation
            att = deserialize_attestation(serialize_attestation(unknown))
        except DeserializationError:
            continue
        # Signature before verify_receipt: that one raises on a root that
        # isn't 32 bytes, and the witness only ever signs 32-byte roots.
        if (
            type(att) is ZeitwerkAttestation
            and att.anchor_type is AnchorType.WITNESS_ED25519
            and len(att.anchor_ref) == KEY_ID_SIZE + SIGNATURE_SIZE
            and att.anchor_ref[:KEY_ID_SIZE] == key_id
            and Signer.verify(pubkey, att.epoch, root, key_id, att.anchor_ref[KEY_ID_SIZE:])
            and verify_receipt(digest, receipt, root)
        ):
            return True
    return False
