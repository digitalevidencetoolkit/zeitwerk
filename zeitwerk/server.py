"""The witness server's HTTP side (issue #17), still half stub.

Same URL shape as an OpenTimestamps calendar, on the stdlib `http.server`:

    POST /digest            32 raw bytes in, pending receipt out
    GET  /timestamp/<hex>   the upgraded receipt, or 404 while pending
    GET  /key               the signer's raw Ed25519 public key

State lives in a data directory, `~/.zeitwerk` by default: the SQLite store
and the signing key, so a restart loses nothing.

    python -m zeitwerk.server
"""

from __future__ import annotations

import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from zeitwerk.epochtree import DIGEST_SIZE, check_digest
from zeitwerk.signer import Signer
from zeitwerk.store import EpochClosed, EpochFull, Store
from zeitwerk.witness import EPOCH_SECONDS, pending_receipt

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 14788
DEFAULT_DATA_DIR = Path.home() / ".zeitwerk"
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
        try:
            self.server.store.add_submission(digest, epoch)  # on disk before we reply
        except EpochClosed:  # the hour closed between reading the clock and here
            return self._reply(503, "Epoch closed, try again")
        except EpochFull:
            return self._reply(503, "Epoch full, try again next hour")
        self._reply(200, receipt, "application/octet-stream")

    def get_timestamp(self, hex_digest: str):
        """Return the upgraded receipt for a fingerprint, or 404 Pending."""
        try:
            digest = bytes.fromhex(hex_digest)
            check_digest(digest)
        except ValueError:
            return self._reply(400, "Expected a 64-character hex digest")
        # Nothing gets upgraded yet: next, a 200 with witness.upgraded_receipt.
        self._reply(404, "Pending" if self.server.store.is_submitted(digest) else "Not found")

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
    data_dir: str | Path,
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    now=time.time,
) -> ThreadingHTTPServer:
    """`data_dir` holds the database and the signing key; reuse it to restart.

    `now` is swappable so the tests don't have to wait an hour.
    """
    data_dir = Path(data_dir)
    data_dir.mkdir(mode=0o700, parents=True, exist_ok=True)  # the private key lives here
    server = ThreadingHTTPServer((host, port), Handler)
    # Hung on the server so the handlers can get at them via self.server.
    server.now = now
    server.store = Store(data_dir / "zeitwerk.db")
    server.signer = Signer(data_dir / "signer.pem")
    return server


def start_closer(server: ThreadingHTTPServer, interval: float = 60.0) -> threading.Thread:
    """Call witness.close_due every `interval` seconds, in a daemon thread.

    Uses the server's own store, signer and clock. main() starts it next to
    serve_forever; the tests call close_due directly with a fake clock.
    """
    raise NotImplementedError


def main() -> None:
    server = make_server(DEFAULT_DATA_DIR)
    print(f"zeitwerk witness (stub) on http://{DEFAULT_HOST}:{DEFAULT_PORT}")
    server.serve_forever()


if __name__ == "__main__":
    main()
