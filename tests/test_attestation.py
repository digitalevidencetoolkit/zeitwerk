"""Round-trip tests for the zeitwerk attestation wire format.

Runs with the stdlib: `python3 -m unittest discover tests`.
"""

import unittest

import zeitwerk  # noqa: F401  (runs the python-opentimestamps path shim)
from zeitwerk.attestation import (
    ANCHORED_TAG,
    MAX_PAYLOAD_SIZE,
    PENDING_TAG,
    AnchorType,
    ZeitwerkAttestation,
    ZeitwerkPendingAttestation,
    deserialize_attestation,
    serialize_attestation,
)

from opentimestamps.core.notary import TimeAttestation, UnknownAttestation
from opentimestamps.core.serialize import (
    BytesDeserializationContext,
    BytesSerializationContext,
    DeserializationError,
)


def _frame(tag, payload):
    """Wrap a raw payload in OTS attestation framing (TAG + varbytes)."""
    ctx = BytesSerializationContext()
    ctx.write_bytes(tag)
    ctx.write_varbytes(payload)
    return ctx.getbytes()


class PendingAttestationTests(unittest.TestCase):
    def test_wire_round_trips(self):
        att = ZeitwerkPendingAttestation(
            epoch_submit=12345,
            recover_uri="https://recover.zeitwerk.example/epoch",
        )
        self.assertEqual(att, deserialize_attestation(serialize_attestation(att)))

    def test_rejects_bad_uri_characters(self):
        with self.assertRaises(ValueError):
            ZeitwerkPendingAttestation(epoch_submit=1, recover_uri="has spaces")

    def test_rejects_trailing_bytes(self):
        good = serialize_attestation(ZeitwerkPendingAttestation(1, "https://a.example"))
        with self.assertRaises(DeserializationError):
            deserialize_attestation(good + b"\x00")

    def test_malformed_uri_on_wire_reads_as_deserialization_error(self):
        payload = BytesSerializationContext()
        payload.write_varuint(1)
        payload.write_varbytes(b"has spaces")  # disallowed URI char
        with self.assertRaises(DeserializationError):
            deserialize_attestation(_frame(PENDING_TAG, payload.getbytes()))


class AnchoredAttestationTests(unittest.TestCase):
    def test_wire_round_trips(self):
        att = ZeitwerkAttestation(
            epoch=12345,
            anchor_type=AnchorType.TSA_RFC3161,
            anchor_ref=bytes.fromhex("deadbeefcafe"),
        )
        self.assertEqual(att, deserialize_attestation(serialize_attestation(att)))

    def test_all_anchor_types_round_trip(self):
        for anchor_type in AnchorType:
            att = ZeitwerkAttestation(epoch=7, anchor_type=anchor_type, anchor_ref=b"x")
            restored = deserialize_attestation(serialize_attestation(att))
            self.assertEqual(att.anchor_type, restored.anchor_type)

    def test_oversized_payload_rejected_on_deserialize(self):
        att = ZeitwerkAttestation(
            epoch=0,
            anchor_type=AnchorType.TSA_RFC3161,
            anchor_ref=b"\x00" * (MAX_PAYLOAD_SIZE + 1),
        )
        with self.assertRaises(DeserializationError):
            deserialize_attestation(serialize_attestation(att))

    def test_unknown_anchor_type_reads_as_deserialization_error(self):
        payload = BytesSerializationContext()
        payload.write_varuint(0)
        payload.write_uint8(99)  # not a defined AnchorType
        payload.write_varbytes(b"")
        with self.assertRaises(DeserializationError):
            deserialize_attestation(_frame(ANCHORED_TAG, payload.getbytes()))


class OrderingTests(unittest.TestCase):
    def test_same_type_sorts_by_fields(self):
        a = ZeitwerkAttestation(1, AnchorType.TSA_RFC3161, b"a")
        b = ZeitwerkAttestation(2, AnchorType.TSA_RFC3161, b"b")
        self.assertEqual(sorted([b, a]), [a, b])

    def test_cross_type_orders_by_tag(self):
        pend = ZeitwerkPendingAttestation(1, "https://a.example")
        anch = ZeitwerkAttestation(1, AnchorType.TSA_RFC3161, b"a")
        # ANCHORED_TAG < PENDING_TAG bytewise, so the anchored leaf sorts first.
        self.assertLess(ANCHORED_TAG, PENDING_TAG)
        self.assertEqual(sorted([pend, anch]), [anch, pend])


class OtsInteropTests(unittest.TestCase):
    def test_stock_ots_parser_sees_unknown_attestation(self):
        """Stage 1 success criterion: a stock OTS client degrades ours to
        UnknownAttestation rather than raising."""
        att = ZeitwerkAttestation(
            epoch=99, anchor_type=AnchorType.FEDERATED_COSIGN, anchor_ref=b"ref"
        )
        wire = serialize_attestation(att)

        stock = TimeAttestation.deserialize(BytesDeserializationContext(wire))
        self.assertIsInstance(stock, UnknownAttestation)
        self.assertEqual(stock.TAG, att.TAG)


if __name__ == "__main__":
    unittest.main()
