"""zeitwerk attestation types — the leaf that terminates a timestamp proof.

Two-state lifecycle, mirroring OpenTimestamps:

    ZeitwerkPendingAttestation   submitted, not yet anchored
    ZeitwerkAttestation          anchored, self-verifying

The wire format and (de)serialization are not implemented yet — see the method
stubs below. These are `TimeAttestation` subclasses so they slot into the OTS
tagged-type registry.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum

from opentimestamps.core.notary import (
    PendingAttestation,
    TimeAttestation,
    UnknownAttestation,
)
from opentimestamps.core.serialize import (
    BytesDeserializationContext,
    BytesSerializationContext,
    DeserializationError,
)

# Inherited from the OTS base; re-exported so callers/tests have one import site.
MAX_PAYLOAD_SIZE = TimeAttestation.MAX_PAYLOAD_SIZE

# 8-byte tags. OpenTimestamps picks these at random and freezes them forever so
# the tagged-type registry never collides.
# TODO(#8): allocate the final random tags and freeze before any receipt ships.
PENDING_TAG = bytes.fromhex("005a45495450454e")  # "\x00ZEITPEN", placeholder
ANCHORED_TAG = bytes.fromhex("005a454954414e43")  # "\x00ZEITANC", placeholder


class AnchorType(IntEnum):
    """How an anchored root was witnessed. See open question 1 in the plan."""

    TSA_RFC3161 = 0  # centralized signed timestamp (simplest)
    FEDERATED_COSIGN = 1  # N-of-M independent signers
    TRANSPARENCY_LOG = 2  # transparency log with external witnesses


@dataclass(frozen=True)
class ZeitwerkPendingAttestation(TimeAttestation):
    """Submitted to zeitwerk but not yet anchored."""

    TAG = PENDING_TAG

    epoch_submit: int
    recover_uri: str

    def __post_init__(self) -> None:
        PendingAttestation.check_uri(self.recover_uri.encode())

    def __lt__(self, other: object) -> bool:
        if other.__class__ is ZeitwerkPendingAttestation:
            return (self.epoch_submit, self.recover_uri) < (
                other.epoch_submit,
                other.recover_uri,
            )
        return super().__lt__(other)

    def _serialize_payload(self, ctx: BytesSerializationContext) -> None:
        ctx.write_varuint(self.epoch_submit)
        ctx.write_varbytes(self.recover_uri.encode())

    @classmethod
    def deserialize(cls, ctx: BytesDeserializationContext) -> "ZeitwerkPendingAttestation":
        epoch_submit = ctx.read_varuint()
        uri_bytes = ctx.read_varbytes(PendingAttestation.MAX_URI_LENGTH)
        try:  # bad UTF-8 or a disallowed URI char must read as a wire error
            return cls(epoch_submit=epoch_submit, recover_uri=uri_bytes.decode())
        except ValueError as exc:
            raise DeserializationError(f"invalid zeitwerk pending payload: {exc!r}") from exc


@dataclass(frozen=True)
class ZeitwerkAttestation(TimeAttestation):
    """Anchored and self-verifying."""

    TAG = ANCHORED_TAG

    epoch: int
    anchor_type: AnchorType
    anchor_ref: bytes

    def __lt__(self, other: object) -> bool:
        if other.__class__ is ZeitwerkAttestation:
            return (self.epoch, self.anchor_type, self.anchor_ref) < (
                other.epoch,
                other.anchor_type,
                other.anchor_ref,
            )
        return super().__lt__(other)

    def _serialize_payload(self, ctx: BytesSerializationContext) -> None:
        ctx.write_varuint(self.epoch)
        ctx.write_uint8(int(self.anchor_type))
        ctx.write_varbytes(self.anchor_ref)

    @classmethod
    def deserialize(cls, ctx: BytesDeserializationContext) -> "ZeitwerkAttestation":
        epoch = ctx.read_varuint()
        try:  # a byte that isn't a defined AnchorType must read as a wire error
            anchor_type = AnchorType(ctx.read_uint8())
        except ValueError as exc:
            raise DeserializationError(f"invalid zeitwerk anchor_type: {exc!r}") from exc
        anchor_ref = ctx.read_varbytes(cls.MAX_PAYLOAD_SIZE)
        return cls(epoch=epoch, anchor_type=anchor_type, anchor_ref=anchor_ref)


# --- wire helpers ------------------------------------------------------------

_REGISTRY = {
    ZeitwerkPendingAttestation.TAG: ZeitwerkPendingAttestation,
    ZeitwerkAttestation.TAG: ZeitwerkAttestation,
}


def serialize_attestation(att: TimeAttestation) -> bytes:
    """Serialize any TimeAttestation to OTS wire bytes (TAG + varbytes payload)."""
    ctx = BytesSerializationContext()
    att.serialize(ctx)
    return ctx.getbytes()


def deserialize_attestation(buf: bytes) -> TimeAttestation:
    """Parse OTS wire bytes back to an attestation.

    zeitwerk tags decode to their typed class; any other tag decodes to
    `UnknownAttestation` — the same graceful degradation a stock OTS client does.
    """
    ctx = BytesDeserializationContext(buf)
    tag = ctx.read_bytes(TimeAttestation.TAG_SIZE)
    payload = ctx.read_varbytes(TimeAttestation.MAX_PAYLOAD_SIZE)
    ctx.assert_eof()

    cls = _REGISTRY.get(tag)
    if cls is None:
        return UnknownAttestation(tag, payload)

    payload_ctx = BytesDeserializationContext(payload)
    att = cls.deserialize(payload_ctx)
    payload_ctx.assert_eof()
    return att
