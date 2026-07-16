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

__all__ = [
    "AnchorType",
    "ZeitwerkAttestation",
    "ZeitwerkPendingAttestation",
    "deserialize_attestation",
    "serialize_attestation",
]
