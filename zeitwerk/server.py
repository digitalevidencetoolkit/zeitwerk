"""The witness server's HTTP surface — draft stubs (issue #17).

Same URL shape as an OpenTimestamps calendar, on the stdlib `http.server`:

    POST /digest            32 raw bytes in, pending receipt out
    GET  /timestamp/<hex>   the upgraded receipt, or 404 while pending
    GET  /key               the signer's public key

Every route answers 501 for now; the witness behind them comes later.

    python -m zeitwerk.server
"""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 14788


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
        self._reply(501, "Not implemented")

    def get_timestamp(self, hex_digest: str):
        """Return the upgraded receipt for a fingerprint, or 404 Pending."""
        self._reply(501, "Not implemented")

    def get_key(self):
        """Return the signer's raw Ed25519 public key."""
        self._reply(501, "Not implemented")

    def _reply(self, status: int, text: str) -> None:
        body = text.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        """Log nothing: no client IPs are collected."""


def make_server(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT) -> ThreadingHTTPServer:
    return ThreadingHTTPServer((host, port), Handler)


def main() -> None:
    server = make_server()
    print(f"zeitwerk witness (stub) on http://{DEFAULT_HOST}:{DEFAULT_PORT}")
    server.serve_forever()


if __name__ == "__main__":
    main()
