"""Tests for the witness server's HTTP routes.

Runs with the stdlib: `python3 -m unittest discover tests`.
"""

import http.client
import tempfile
import threading
import unittest

import zeitwerk  # noqa: F401  (runs the python-opentimestamps path shim)
from opentimestamps.core.serialize import BytesDeserializationContext
from opentimestamps.core.timestamp import Timestamp
from zeitwerk import ZeitwerkPendingAttestation, deserialize_attestation, serialize_attestation
from zeitwerk.server import RECOVER_URI, make_server
from zeitwerk.store import Store

FAKE_NOW = 7 * 3600 + 12  # 07:00:12 UTC on 1 January 1970, so epoch 7


def start(data_dir):
    server = make_server(data_dir, port=0, now=lambda: FAKE_NOW)
    # A short poll so shutdown() doesn't wait half a second each restart.
    threading.Thread(target=server.serve_forever, args=(0.01,), daemon=True).start()
    return server


def stop(server):
    server.shutdown()
    server.server_close()
    server.store.close()


def request(server, method, path, body=None):
    conn = http.client.HTTPConnection("127.0.0.1", server.server_address[1])
    try:
        conn.request(method, path, body=body)
        resp = conn.getresponse()
        return resp.status, resp.read()
    finally:
        conn.close()


class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.server = start(cls.tmp.name)

    @classmethod
    def tearDownClass(cls):
        stop(cls.server)
        cls.tmp.cleanup()

    def _request(self, method, path, body=None):
        return request(self.server, method, path, body)

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

    def test_get_key_returns_public_key(self):
        status, body = self._request("GET", "/key")
        self.assertEqual(status, 200)
        self.assertEqual(len(body), 32)  # Ed25519 public key is 32 bytes

    def test_unknown_path_is_404(self):
        self.assertEqual(self._status("GET", "/nope"), 404)


class ServerRestartTests(unittest.TestCase):
    """A restart on the same data directory loses nothing."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.data_dir = tmp.name

    def _restart(self, server):
        stop(server)
        server = start(self.data_dir)
        self.addCleanup(stop, server)
        return server

    def test_a_submission_is_still_pending_after_a_restart(self):
        digest = b"\x05" * 32
        server = start(self.data_dir)
        request(server, "POST", "/digest", digest)
        server = self._restart(server)
        self.assertEqual(request(server, "GET", "/timestamp/" + digest.hex()), (404, b"Pending"))

    def test_the_key_is_the_same_after_a_restart(self):
        server = start(self.data_dir)
        before = request(server, "GET", "/key")
        server = self._restart(server)
        self.assertEqual(request(server, "GET", "/key"), before)


class ServerRefusalTests(unittest.TestCase):
    """When the store turns a submission away, the client still gets an answer."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.server = start(tmp.name)
        self.addCleanup(stop, self.server)

    def test_a_closed_epoch_is_503(self):
        self.server.store.close_epoch(7)  # the closer got there between the clock and the store
        self.assertEqual(
            request(self.server, "POST", "/digest", b"\x06" * 32),
            (503, b"Epoch closed, try again"),
        )

    def test_a_full_epoch_is_503(self):
        self.server.store.close()
        self.server.store = Store(":memory:", max_leaves=1)
        request(self.server, "POST", "/digest", b"\x06" * 32)
        self.assertEqual(
            request(self.server, "POST", "/digest", b"\x07" * 32),
            (503, b"Epoch full, try again next hour"),
        )


if __name__ == "__main__":
    unittest.main()
