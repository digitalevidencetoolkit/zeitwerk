"""Witness's state in SQLite

Each epoch (hour) collects fingerprint submissions. A submission is a
(digest, epoch) pair. The same digest in the same epoch is a no-op;
the same digest in different epochs is stored twice.

An epoch can hold at most MAX_LEAVES (2^20) unique digests. Once that limit
is reached, the epoch is considered full and no more submissions are accepted
for it. This prevents an epoch from never closing.

Thread safety: every write (add_submission, close_epoch, seal_epoch) acquires
a lock and runs as a single SQLite transaction. Reads that must be
consistent with the latest write (is_submitted) also use the lock.
"""

from __future__ import annotations

import sqlite3
import threading
from pathlib import Path

from zeitwerk.epochtree import MAX_LEAVES, DIGEST_SIZE, check_digest

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

# Maximum number of unique digests per epoch
MAX_EPOCH_LEAVES = MAX_LEAVES


class EpochClosed(Exception):
    """The hour has closed: submit to the current one instead."""


class EpochFull(Exception):
    """The hour has reached MAX_EPOCH_LEAVES unique digests and cannot accept more."""


class Store:
    """One connection, shared by the request threads and the closer.

    `":memory:"` works too, for tests.
    
    Args:
        path: Database path or ":memory:" for in-memory DB
        max_leaves: Maximum unique digests per epoch (default: MAX_EPOCH_LEAVES = 2^20)
                   Used for testing with smaller limits.
    """

    def __init__(self, path: str | Path, max_leaves: int = MAX_EPOCH_LEAVES):
        if not 0 < max_leaves <= MAX_EPOCH_LEAVES:
            raise ValueError(f"max_leaves must be in 1..{MAX_EPOCH_LEAVES}, got {max_leaves}")
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.executescript(SCHEMA)
        self._lock = threading.Lock()  # one transaction at a time
        self._max_leaves = max_leaves

    def close(self) -> None:
        """Close the database connection (not an epoch: see close_epoch)."""
        self._conn.close()

    def add_submission(self, digest: bytes, epoch: int) -> None:
        """Record a fingerprint for an hour; EpochClosed once that hour has closed.
        
        If the same digest is submitted twice in the same epoch, the second
        submission is a no-op (no error, no duplicate row).
        
        Raises EpochClosed if the epoch has already been closed.
        Raises EpochFull if the epoch has reached MAX_EPOCH_LEAVES unique digests.
        """
        check_digest(digest)
        with self._lock:
            cursor = self._conn.cursor()
            try:
                # Check if epoch is closed
                cursor.execute(
                    "SELECT leaf_set FROM epochs WHERE epoch = ?", (epoch,)
                )
                row = cursor.fetchone()
                if row is not None:
                    raise EpochClosed(f"epoch {epoch} is already closed")
                
                # Count current unique digests in this epoch
                cursor.execute(
                    "SELECT COUNT(*) FROM submissions WHERE epoch = ?", (epoch,)
                )
                count = cursor.fetchone()[0]
                if count >= self._max_leaves:
                    # Check if this specific digest is already in the epoch
                    cursor.execute(
                        "SELECT 1 FROM submissions WHERE digest = ? AND epoch = ?",
                        (digest, epoch)
                    )
                    if cursor.fetchone() is None:
                        raise EpochFull(
                            f"epoch {epoch} is full ({self._max_leaves} leaves)"
                        )
                
                # Insert or ignore (no-op if already exists)
                cursor.execute(
                    "INSERT OR IGNORE INTO submissions (digest, epoch) VALUES (?, ?)",
                    (digest, epoch)
                )
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise

    def is_submitted(self, digest: bytes) -> bool:
        """Has this fingerprint come in, in any hour?
        
        Returns True if the digest has been submitted to any epoch (closed or open).
        """
        check_digest(digest)
        with self._lock:
            cursor = self._conn.cursor()
            cursor.execute(
                "SELECT 1 FROM submissions WHERE digest = ? LIMIT 1", (digest,)
            )
            return cursor.fetchone() is not None

    def close_epoch(self, epoch: int) -> bytes:
        """Freeze an hour's leaf set, turn latecomers away, return the leaf set.
        Closing again returns the same leaf set.
        """
        with self._lock:
            cursor = self._conn.cursor()
            try:
                # Check if already closed
                cursor.execute(
                    "SELECT leaf_set FROM epochs WHERE epoch = ?", (epoch,)
                )
                row = cursor.fetchone()
                if row is not None:
                    return row[0]  # Already closed, return existing leaf_set
                
                # Get all digests for this epoch, sorted
                cursor.execute(
                    "SELECT digest FROM submissions WHERE epoch = ? ORDER BY digest",
                    (epoch,)
                )
                digests = [row[0] for row in cursor.fetchall()]
                
                # Build leaf_set (sorted, deduplicated - already done by DB)
                leaf_set = b"".join(digests)
                
                # Store in epochs table
                cursor.execute(
                    "INSERT OR REPLACE INTO epochs (epoch, leaf_set) VALUES (?, ?)",
                    (epoch, leaf_set)
                )
                self._conn.commit()
                return leaf_set
            except Exception:
                self._conn.rollback()
                raise

    def seal_epoch(self, epoch: int, root: bytes, attestation: bytes) -> None:
        """Store a closed hour's root and serialized attestation, once."""
        if len(root) != DIGEST_SIZE:
            raise ValueError(f"root must be {DIGEST_SIZE} bytes, got {len(root)}")
        
        with self._lock:
            cursor = self._conn.cursor()
            try:
                # Check that epoch is closed (has a row) and not yet sealed
                cursor.execute(
                    "SELECT attestation FROM epochs WHERE epoch = ?", (epoch,)
                )
                row = cursor.fetchone()
                if row is None:
                    raise ValueError(f"epoch {epoch} has not been closed yet")
                if row[0] is not None:
                    raise ValueError(f"epoch {epoch} is already sealed")
                
                # Update with root and attestation
                cursor.execute(
                    """UPDATE epochs 
                       SET root = ?, attestation = ? 
                       WHERE epoch = ?""",
                    (root, attestation, epoch)
                )
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise

    def unsealed_epochs(self, before: int) -> list[int]:
        """Hours older than `before` that have submissions but no seal, oldest first.

        Takes in an hour that was closed but never sealed (a crash between
        close_epoch and seal_epoch), so the closer picks it back up. An hour
        with no submissions never shows up: there is nothing to publish.
        """
        with self._lock:
            cursor = self._conn.cursor()
            cursor.execute(
                """SELECT DISTINCT s.epoch FROM submissions s
                   LEFT JOIN epochs e ON e.epoch = s.epoch
                   WHERE s.epoch < ? AND e.attestation IS NULL
                   ORDER BY s.epoch""",
                (before,)
            )
            return [row[0] for row in cursor.fetchall()]

    def sealed_for(self, digest: bytes) -> tuple[bytes, bytes] | None:
        """The earliest sealed hour holding this fingerprint, or None.

        Returns that hour's (leaf_set, attestation), just what recover_receipt
        needs to rebuild the receipt. None while it is pending, or unknown.
        """
        check_digest(digest)
        with self._lock:
            cursor = self._conn.cursor()
            cursor.execute(
                """SELECT e.leaf_set, e.attestation FROM submissions s
                   JOIN epochs e ON e.epoch = s.epoch
                   WHERE s.digest = ?  AND e.attestation IS NOT NULL
                   ORDER BY s.epoch LIMIT 1""",
                (digest,)
            )
            return cursor.fetchone()  # already a (leaf_set, attestation) tuple
