"""The witness server's HTTP side (issue #17), still half stub.

Same URL shape as an OpenTimestamps calendar, on the stdlib `http.server`:

    POST /digest            32 raw bytes in, pending receipt out
    GET  /timestamp/<hex>   the upgraded receipt, or 404 while pending
    GET  /key               the signer's raw Ed25519 public key

For now submissions just sit in a set in memory, so a restart forgets them
(the SQLite store will fix that).

    python -m zeitwerk.server
"""

from __future__ import annotations

import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from zeitwerk.epochtree import DIGEST_SIZE, check_digest
from zeitwerk.signer import Signer
from zeitwerk.witness import EPOCH_SECONDS, pending_receipt

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 14788
RECOVER_URI = f"http://{DEFAULT_HOST}:{DEFAULT_PORT}"


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path == "/digest":
            self.post_digest()
        else:
            self._reply(404, "Not found")

    def do_GET(self):
        if self.path.startswith("/timestamp/"):
            self.get_timestamp(self.path[len("/timestamp/") :])
        elif self.path == "/key":
            self.get_key()
        else:
            self._reply(404, "Not found")

    def post_digest(self):
        """Accept a 32-byte fingerprint; return its pending receipt."""
        try:
            length = int(self.headers["Content-Length"])
            if not 0 <= length <= 2 * DIGEST_SIZE:  # we're after 32 bytes, no point reading a big body
                raise ValueError(length)
            digest = self.rfile.read(length)
            epoch = int(self.server.now()) // EPOCH_SECONDS
            receipt = pending_receipt(digest, epoch, RECOVER_URI)
        except (TypeError, ValueError):  # no Content-Length, a silly one, or just not 32 bytes
            return self._reply(400, "Expected a 32-byte digest")
        self.server.submitted.add(digest)
        self._reply(200, receipt, "application/octet-stream")

    def get_timestamp(self, hex_digest: str):
        """Return the upgraded receipt for a fingerprint, or 404 Pending."""
        try:
            digest = bytes.fromhex(hex_digest)
            check_digest(digest)
        except ValueError:
            return self._reply(400, "Expected a 64-character hex digest")
        # Nothing gets upgraded yet, that waits for the hourly closer.
        self._reply(404, "Pending" if digest in self.server.submitted else "Not found")

    def get_key(self):
        """Return the signer's raw Ed25519 public key."""
        self._reply(200, self.server.signer.public_key, "application/octet-stream")

    def _reply(self, status: int, body: str | bytes, content_type: str = "text/plain") -> None:
        if isinstance(body, str):
            body = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        """Log nothing: no client IPs are collected."""


def make_server(
    host: str = DEFAULT_HOST, port: int = DEFAULT_PORT, now=time.time
) -> ThreadingHTTPServer:
    """`now` is swappable so the tests don't have to wait an hour."""
    server = ThreadingHTTPServer((host, port), Handler)
    # Hung on the server so the handlers can get at them via self.server.
    server.now = now
    server.submitted = set()
    server.signer = Signer()
    return server


def main() -> None:
    server = make_server()
    print(f"zeitwerk witness (stub) on http://{DEFAULT_HOST}:{DEFAULT_PORT}")
    server.serve_forever()


if __name__ == "__main__":
    main()
