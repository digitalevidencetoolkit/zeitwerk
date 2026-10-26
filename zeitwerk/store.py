"""Witness's state in SQLite
Draft stub
"""

from __future__ import annotations

import sqlite3
import threading
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS submissions (
    digest BLOB NOT NULL,
    epoch  INTEGER NOT NULL,
    PRIMARY KEY (digest, epoch)
);
CREATE TABLE IF NOT EXISTS epochs (
    epoch       INTEGER PRIMARY KEY,
    leaf_set    BLOB NOT NULL,  -- frozen at close
    root        BLOB,           -- NULL until sealed
    attestation BLOB            -- NULL until sealed
);
"""


class EpochClosed(Exception):
    """The hour has closed: submit to the current one instead."""

class Store:
    """One connection, shared by the request threads and the closer.

    `":memory:"` works too, for tests.
    """

    def __init__(self, path: str | Path):
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.executescript(SCHEMA)
        self._lock = threading.Lock()  # one transaction at a time

    def close(self) -> None:
        """Close the database connection (not an epoch: see close_epoch)."""
        self._conn.close()

    def add_submission(self, digest: bytes, epoch: int) -> None:
        """Record a fingerprint for an hour; EpochClosed once that hour has closed."""
        raise NotImplementedError("add_submission: not implemented yet")

    def is_submitted(self, digest: bytes) -> bool:
        """Has this fingerprint come in, in any hour?"""
        raise NotImplementedError("is_submitted: not implemented yet")

    def close_epoch(self, epoch: int) -> bytes:
        """Freeze an hour's leaf set, turn latecomers away, return the leaf set.
        Closing again returns the same leaf set.
        """
        raise NotImplementedError("close_epoch: not implemented yet")

    def seal_epoch(self, epoch: int, root: bytes, attestation: bytes) -> None:
        """Store a closed hour's root and serialized attestation, once."""
        raise NotImplementedError("seal_epoch: not implemented yet")
