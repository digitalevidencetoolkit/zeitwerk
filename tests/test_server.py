"""Tests for the witness server's HTTP routes.

Runs with the stdlib: `python3 -m unittest discover tests`.
"""

import http.client
import threading
import unittest

import zeitwerk  # noqa: F401  (runs the python-opentimestamps path shim)
from opentimestamps.core.serialize import BytesDeserializationContext
from opentimestamps.core.timestamp import Timestamp
from zeitwerk import ZeitwerkPendingAttestation, deserialize_attestation, serialize_attestation
from zeitwerk.server import RECOVER_URI, make_server

FAKE_NOW = 7 * 3600 + 12  # 07:00:12 UTC on 1 January 1970, so epoch 7


class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = make_server(port=0, now=lambda: FAKE_NOW)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def _request(self, method, path, body=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port)
        try:
            conn.request(method, path, body=body)
            resp = conn.getresponse()
            return resp.status, resp.read()
        finally:
            conn.close()

    def _status(self, method, path, body=None):
        return self._request(method, path, body)[0]

    def test_post_digest_returns_a_receipt_pending_in_the_clocks_epoch(self):
        digest = b"\x01" * 32
        _, body = self._request("POST", "/digest", digest)
        stamp = Timestamp.deserialize(BytesDeserializationContext(body), digest)
        # Stock OTS doesn't know our tag and parses it as UnknownAttestation,
        # hence the round trip through ours before comparing.
        [(_, attestation)] = stamp.all_attestations()
        self.assertEqual(
            deserialize_attestation(serialize_attestation(attestation)),
            ZeitwerkPendingAttestation(epoch_submit=7, recover_uri=RECOVER_URI),
        )

    def test_post_digest_rejects_anything_but_32_bytes(self):
        for size in (0, 31, 33):
            with self.subTest(size=size):
                self.assertEqual(self._status("POST", "/digest", b"\x00" * size), 400)

    def test_same_digest_twice_gets_identical_receipts(self):
        digest = b"\x02" * 32
        first = self._request("POST", "/digest", digest)
        self.assertEqual(first, self._request("POST", "/digest", digest))

    def test_get_timestamp_rejects_bad_hex(self):
        for hex_digest in ("zz" * 32, "00" * 31):
            with self.subTest(hex_digest=hex_digest):
                self.assertEqual(self._status("GET", "/timestamp/" + hex_digest), 400)

    def test_get_timestamp_is_pending_once_submitted(self):
        digest = b"\x03" * 32
        self._request("POST", "/digest", digest)
        self.assertEqual(self._request("GET", "/timestamp/" + digest.hex()), (404, b"Pending"))

    def test_get_timestamp_is_not_found_when_never_submitted(self):
        self.assertEqual(self._request("GET", "/timestamp/" + "04" * 32), (404, b"Not found"))

    def test_get_key_is_not_implemented(self):
        self.assertEqual(self._status("GET", "/key"), 501)

    def test_unknown_path_is_404(self):
        self.assertEqual(self._status("GET", "/nope"), 404)


if __name__ == "__main__":
    unittest.main()
