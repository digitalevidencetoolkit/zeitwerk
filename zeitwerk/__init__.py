"""zeitwerk — RFC 3161-spirited timestamping with OpenTimestamps-compatible receipts.
"""

# Dev shim: put the vendored python-opentimestamps on the path if it isn't
# installed. Replace with `pip install -e submodules/python-opentimestamps`.
try:
    import opentimestamps  # noqa: F401
except ModuleNotFoundError:
    import os
    import sys

    sys.path.insert(
        0,
        os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "submodules", "python-opentimestamps")
        ),
    )

from zeitwerk.attestation import (
    AnchorType,
    ZeitwerkAttestation,
    ZeitwerkPendingAttestation,
    deserialize_attestation,
    serialize_attestation,
)
from zeitwerk.aggregator import Aggregator, ClosedEpoch
from zeitwerk.epochtree import (
    EpochTree,
    build_epoch_tree,
    decode_leaf_set,
    encode_leaf_set,
    recover_receipt,
    verify_inclusion,
    verify_non_inclusion,
    verify_receipt,
)

__all__ = [
    "Aggregator",
    "AnchorType",
    "ClosedEpoch",
    "EpochTree",
    "ZeitwerkAttestation",
    "ZeitwerkPendingAttestation",
    "build_epoch_tree",
    "decode_leaf_set",
    "deserialize_attestation",
    "encode_leaf_set",
    "recover_receipt",
    "serialize_attestation",
    "verify_inclusion",
    "verify_non_inclusion",
    "verify_receipt",
]
