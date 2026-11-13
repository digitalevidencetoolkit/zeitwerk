"""The witness server's HTTP side (issue #17).

Same URL shape as an OpenTimestamps calendar, on the stdlib `http.server`:

    POST /digest            32 raw bytes in, pending receipt out
    GET  /timestamp/<hex>   the upgraded receipt, or 404 while pending
    GET  /recover/<hex>     the receipt rebuilt from the published set, with
                            only the fingerprint; `?epoch=N` names the hour
    GET  /key               the signer's raw Ed25519 public key

A background thread seals each hour once it is over and publishes it to the
git repo under the data directory (start_closer).

State lives in a data directory, `~/.zeitwerk` by default: the SQLite store,
the signing key and the git repo of published hours, so a restart loses
nothing. Each `--remote name=url` is a git remote the repo pushes to after
every published hour; they are kept in the repo, so once given they stay.

    python -m zeitwerk.server --remote github=git@github.com:org/epochs.git
"""

from __future__ import annotations

import argparse
import logging
import threading
import time
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs

from zeitwerk.epochtree import DIGEST_SIZE, check_digest
from zeitwerk.gitrepo import ensure_repo, set_remote
from zeitwerk.signer import Signer
from zeitwerk.store import EpochClosed, EpochFull, Store
from zeitwerk.witness import (
    EPOCH_SECONDS,
    close_due,
    pending_receipt,
    publish_due,
    recovered_receipt,
    upgraded_receipt,
)

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 14788
DEFAULT_DATA_DIR = Path.home() / ".zeitwerk"
READ_TIMEOUT = 10.0  # seconds a client gets to send its request, then we hang up


class Handler(BaseHTTPRequestHandler):
    # StreamRequestHandler puts this on the socket: a client that stalls
    # mid-request gets hung up on, rather than holding a thread.
    timeout = READ_TIMEOUT

    def do_POST(self):
        if self.path == "/digest":
            self.post_digest()
        else:
            self._reply(404, "Not found")

    def do_GET(self):
        if self.path.startswith("/timestamp/"):
            self.get_timestamp(self.path[len("/timestamp/") :])
        elif self.path.startswith("/recover/"):
            self.get_recover(self.path[len("/recover/") :])
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
            receipt = pending_receipt(digest, epoch, self.server.recover_uri)
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
        receipt = upgraded_receipt(self.server.store, digest)
        if receipt is not None:
            return self._reply(200, receipt, "application/octet-stream")
        self._reply(404, "Pending" if self.server.store.is_submitted(digest) else "Not found")

    def get_recover(self, rest: str):
        """Rebuild the receipt for a fingerprint from what was published (issue #22).

        Without `?epoch=N`, the store's index names the earliest sealed hour
        holding it. With it, the answer comes from the published folder for
        that hour alone, database or no database.
        """
        hex_digest, _, query = rest.partition("?")
        try:
            digest = bytes.fromhex(hex_digest)
            check_digest(digest)
        except ValueError:
            return self._reply(400, "Expected a 64-character hex digest")
        try:
            epochs = parse_qs(query).get("epoch")
            epoch = int(epochs[0]) if epochs else None
        except (ValueError, OverflowError):
            return self._reply(400, "Expected epoch=<hours since 1970-01-01 UTC>")
        if epoch is None:
            receipt = upgraded_receipt(self.server.store, digest)
        else:
            try:
                receipt = recovered_receipt(self.server.repo, digest, epoch)
            except (ValueError, FileNotFoundError):
                # ValueError: epoch out of range, inconsistent files, corrupt data
                # FileNotFoundError: epoch not published
                return self._reply(404, "Not found")
        if receipt is not None:
            return self._reply(200, receipt, "application/octet-stream")
        self._reply(404, "Not found")

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
    recover_uri: str | None = None,
) -> ThreadingHTTPServer:
    """`data_dir` holds the database and the signing key; reuse it to restart.

    `now` is swappable so the tests don't have to wait an hour.
    `recover_uri` goes into every pending receipt: where its holder comes
    back to. Left out, it is the address the server is bound to, which only
    suits a local run; a public server names its own.
    """
    data_dir = Path(data_dir)
    data_dir.mkdir(mode=0o700, parents=True, exist_ok=True)  # the private key lives here
    server = ThreadingHTTPServer((host, port), Handler)
    # Hung on the server so the handlers can get at them via self.server.
    server.now = now
    bound_host, bound_port = server.server_address[:2]  # port=0 gets a real one here
    server.recover_uri = recover_uri or f"http://{bound_host}:{bound_port}"
    server.store = Store(data_dir / "zeitwerk.db")
    server.signer = Signer(data_dir / "signer.pem")
    server.repo = data_dir / "repo"
    ensure_repo(server.repo)
    return server


def start_closer(server: ThreadingHTTPServer, interval: float = 60.0) -> Callable[[], None]:
    """Call witness.close_due every `interval` seconds, in a daemon thread.

    Uses the server's own store, signer and clock. The first run is straight
    away, so a restart catches up on the hours it missed. Returns a function
    that stops the thread and waits for it.
    """
    stopped = threading.Event()

    def run():
        while True:
            try:
                close_due(server.store, server.signer, server.now())
                publish_due(server.store, server.signer, server.repo)
            except Exception:  # try again next time: a dead closer would strand every receipt
                logging.exception("closer: this run failed")
            if stopped.wait(interval):
                return

    thread = threading.Thread(target=run, name="zeitwerk-closer", daemon=True)
    thread.start()

    def stop():
        stopped.set()
        thread.join()

    return stop


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="python -m zeitwerk.server", description=__doc__.split("\n\n")[0])
    parser.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR, help="store, key and repo (default: %(default)s)")
    parser.add_argument("--host", default=DEFAULT_HOST, help="default: %(default)s")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="default: %(default)s")
    parser.add_argument("--recover-uri", help="what pending receipts point back to (default: the bound address)")
    parser.add_argument(
        "--remote",
        action="append",
        default=[],
        metavar="NAME=URL",
        type=lambda s: tuple(s.split("=", 1)) if "=" in s else parser.error(f"--remote wants NAME=URL, got {s!r}"),
        help="git remote to push every published hour to; repeatable",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    server = make_server(args.data_dir, args.host, args.port, recover_uri=args.recover_uri)
    for name, url in args.remote:
        set_remote(server.repo, name, url)
    start_closer(server)
    print(f"zeitwerk witness on http://{args.host}:{args.port}, publishing to {server.repo}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
