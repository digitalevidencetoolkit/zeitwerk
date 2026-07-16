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

from opentimestamps.core.notary import TimeAttestation

# 8-byte tagged-type tags. Placeholders — freeze final random tags before any
# receipt ships (see issue #8).
PENDING_TAG = bytes.fromhex("005a45495450454e")  # "\x00ZEITPEN"
ANCHORED_TAG = bytes.fromhex("005a454954414e43")  # "\x00ZEITANC"


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

    def _serialize_payload(self, ctx) -> None:
        raise NotImplementedError  # TODO

    @classmethod
    def deserialize(cls, ctx) -> "ZeitwerkPendingAttestation":
        raise NotImplementedError  # TODO


@dataclass(frozen=True)
class ZeitwerkAttestation(TimeAttestation):
    """Anchored and self-verifying."""

    TAG = ANCHORED_TAG

    epoch: int
    anchor_type: AnchorType
    anchor_ref: bytes

    def _serialize_payload(self, ctx) -> None:
        raise NotImplementedError  # TODO

    @classmethod
    def deserialize(cls, ctx) -> "ZeitwerkAttestation":
        raise NotImplementedError  # TODO


def serialize_attestation(att: TimeAttestation) -> bytes:
    """Serialize a TimeAttestation to OTS wire bytes (TAG + varbytes payload)."""
    raise NotImplementedError  # TODO


def deserialize_attestation(buf: bytes) -> TimeAttestation:
    """Parse OTS wire bytes back to an attestation."""
    raise NotImplementedError  # TODO
