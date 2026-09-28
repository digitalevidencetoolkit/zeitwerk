"""Tests for the witness server's HTTP routes (draft stubs).

Runs with the stdlib: `python3 -m unittest discover tests`.
"""

import http.client
import threading
import unittest

import zeitwerk  # noqa: F401  (runs the python-opentimestamps path shim)
from zeitwerk.server import make_server


class ServerStubTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = make_server(port=0)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def _status(self, method, path, body=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port)
        try:
            conn.request(method, path, body=body)
            resp = conn.getresponse()
            resp.read()
            return resp.status
        finally:
            conn.close()

    def test_post_digest_is_not_implemented(self):
        self.assertEqual(self._status("POST", "/digest", b"\x00" * 32), 501)

    def test_get_timestamp_is_not_implemented(self):
        self.assertEqual(self._status("GET", "/timestamp/" + "00" * 32), 501)

    def test_get_key_is_not_implemented(self):
        self.assertEqual(self._status("GET", "/key"), 501)

    def test_unknown_path_is_404(self):
        self.assertEqual(self._status("GET", "/nope"), 404)


if __name__ == "__main__":
    unittest.main()
