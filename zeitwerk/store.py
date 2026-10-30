"""Witness's state in SQLite

Each epoch (hour) collects fingerprint submissions. A submission is a
(digest, epoch) pair. The same digest in the same epoch is a no-op;
the same digest in different epochs is stored twice.

An epoch can hold at most MAX_LEAVES (2^20) unique digests, and turns any
more away: past that, decode_leaf_set would refuse its leaf set and the hour
could never be sealed.

Thread safety: one connection, one lock. Every call takes the lock, and each
write is a single SQLite transaction.
"""

from __future__ import annotations

import sqlite3
import threading
from pathlib import Path

from zeitwerk.epochtree import MAX_LEAVES, check_digest

SCHEMA = """
CREATE TABLE IF NOT EXISTS submissions (
    digest BLOB NOT NULL,
    epoch  INTEGER NOT NULL,
    PRIMARY KEY (digest, epoch)
);
-- The primary key serves lookups by digest; this one, everything by hour.
CREATE INDEX IF NOT EXISTS submissions_by_epoch ON submissions (epoch, digest);
CREATE TABLE IF NOT EXISTS epochs (
    epoch       INTEGER PRIMARY KEY,
    leaf_set    BLOB NOT NULL,  -- frozen at close
    root        BLOB,           -- NULL until sealed
    attestation BLOB            -- NULL until sealed
);
"""


class EpochClosed(Exception):
    """The hour has closed: submit to the current one instead."""


class EpochFull(Exception):
    """The hour holds max_leaves unique digests and cannot accept more."""


class Store:
    """One connection, shared by the request threads and the closer.

    `path` can be `":memory:"`, and `max_leaves` lower than MAX_LEAVES, for tests.
    """

    def __init__(self, path: str | Path, max_leaves: int = MAX_LEAVES):
        if not 0 < max_leaves <= MAX_LEAVES:
            raise ValueError(f"max_leaves must be in 1..{MAX_LEAVES}, got {max_leaves}")
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.executescript(SCHEMA)
        self._lock = threading.Lock()  # one transaction at a time
        self._max_leaves = max_leaves

    def close(self) -> None:
        """Close the database connection (not an epoch: see close_epoch)."""
        self._conn.close()

    def add_submission(self, digest: bytes, epoch: int) -> None:
        """Record a fingerprint for an hour; the same one twice is a no-op.

        Raises EpochClosed once that hour has closed, and EpochFull once it
        holds max_leaves unique digests.
        """
        check_digest(digest)
        with self._lock, self._conn:  # commits, or rolls back on an exception
            if self._conn.execute("SELECT 1 FROM epochs WHERE epoch = ?", (epoch,)).fetchone():
                raise EpochClosed(f"epoch {epoch} is already closed")
            if self._conn.execute(
                "SELECT 1 FROM submissions WHERE digest = ? AND epoch = ?", (digest, epoch)
            ).fetchone():
                return
            (count,) = self._conn.execute(
                "SELECT COUNT(*) FROM submissions WHERE epoch = ?", (epoch,)
            ).fetchone()
            if count >= self._max_leaves:
                raise EpochFull(f"epoch {epoch} is full ({self._max_leaves} leaves)")
            self._conn.execute(
                "INSERT INTO submissions (digest, epoch) VALUES (?, ?)", (digest, epoch)
            )

    def is_submitted(self, digest: bytes) -> bool:
        """Has this fingerprint come in, in any hour, closed or open?"""
        check_digest(digest)
        with self._lock:
            row = self._conn.execute(
                "SELECT 1 FROM submissions WHERE digest = ? LIMIT 1", (digest,)
            ).fetchone()
            return row is not None

    def close_epoch(self, epoch: int) -> bytes:
        """Freeze an hour's leaf set, turn latecomers away, return the leaf set.
        Closing again returns the same leaf set.
        """
        with self._lock, self._conn:
            row = self._conn.execute(
                "SELECT leaf_set FROM epochs WHERE epoch = ?", (epoch,)
            ).fetchone()
            if row is not None:
                return row[0]
            rows = self._conn.execute(
                "SELECT digest FROM submissions WHERE epoch = ? ORDER BY digest", (epoch,)
            )
            leaf_set = b"".join(digest for (digest,) in rows)  # sorted, and unique per the key
            self._conn.execute(
                "INSERT INTO epochs (epoch, leaf_set) VALUES (?, ?)", (epoch, leaf_set)
            )
            return leaf_set

    def seal_epoch(self, epoch: int, root: bytes, attestation: bytes) -> None:
        """Store a closed hour's root and serialized attestation, once."""
        check_digest(root)
        with self._lock, self._conn:
            row = self._conn.execute(
                "SELECT attestation FROM epochs WHERE epoch = ?", (epoch,)
            ).fetchone()
            if row is None:
                raise ValueError(f"epoch {epoch} has not been closed yet")
            if row[0] is not None:
                raise ValueError(f"epoch {epoch} is already sealed")
            self._conn.execute(
                "UPDATE epochs SET root = ?, attestation = ? WHERE epoch = ?",
                (root, attestation, epoch),
            )

    def unsealed_epochs(self, before: int) -> list[int]:
        """Hours older than `before` that have submissions but no seal, oldest first.

        Takes in an hour that was closed but never sealed (a crash between
        close_epoch and seal_epoch), so the closer picks it back up. An hour
        with no submissions never shows up: there is nothing to publish.
        """
        with self._lock:
            rows = self._conn.execute(
                """SELECT DISTINCT s.epoch FROM submissions s
                   LEFT JOIN epochs e ON e.epoch = s.epoch
                   WHERE s.epoch < ? AND e.attestation IS NULL
                   ORDER BY s.epoch""",
                (before,),
            )
            return [epoch for (epoch,) in rows]

    def sealed_for(self, digest: bytes) -> tuple[bytes, bytes] | None:
        """The earliest sealed hour holding this fingerprint, or None.

        Returns that hour's (leaf_set, attestation), just what recover_receipt
        needs to rebuild the receipt. None while it is pending, or unknown.
        """
        check_digest(digest)
        with self._lock:
            return self._conn.execute(
                """SELECT e.leaf_set, e.attestation FROM submissions s
                   JOIN epochs e ON e.epoch = s.epoch
                   WHERE s.digest = ? AND e.attestation IS NOT NULL
                   ORDER BY s.epoch LIMIT 1""",
                (digest,),
            ).fetchone()  # already a (leaf_set, attestation) tuple
