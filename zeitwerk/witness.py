"""The witness behind the HTTP routes (issue #17).

Only the pending receipt so far — sealing and signing come next.
"""

from __future__ import annotations

from opentimestamps.core.serialize import BytesSerializationContext
from opentimestamps.core.timestamp import Timestamp

from zeitwerk.attestation import ZeitwerkPendingAttestation
from zeitwerk.epochtree import check_digest

EPOCH_SECONDS = 3600


def pending_receipt(digest: bytes, epoch: int, recover_uri: str) -> bytes:
    """Just submitted? Here's your receipt, marked pending until the hour closes."""
    check_digest(digest)
    stamp = Timestamp(digest)
    stamp.attestations.add(ZeitwerkPendingAttestation(epoch, recover_uri))
    # Same three lines as EpochTree.receipt_bytes, fine to repeat for now.
    ctx = BytesSerializationContext()
    stamp.serialize(ctx)
    return ctx.getbytes()
