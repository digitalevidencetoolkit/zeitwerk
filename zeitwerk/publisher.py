"""Publishing and recovery of epoch data to a git repository.

Pure functions for writing and reading epoch data from a repository folder layout.
No git operations here — see gitrepo.py for that.

Layout (per epoch N):
    epochs/YYYY/MM/DD/HH/leaves.bin   -- encoded leaf set
    epochs/YYYY/MM/DD/HH/leaves.hex   -- one hex leaf per line
    epochs/YYYY/MM/DD/HH/root         -- 32-byte root hash
    epochs/YYYY/MM/DD/HH/attestation  -- serialized attestation
    epochs/YYYY/MM/DD/HH/epoch.json   -- metadata: epoch, interval, leaf count, root, key_id(s)

    signers/<key_id>.pub   -- raw 32-byte Ed25519 public key
    signers/<key_id>.json  -- validity window metadata
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from zeitwerk.epochtree import LeafSet
    from zeitwerk.attestation import ZeitwerkAttestation


def epoch_path(epoch: int) -> str:
    """Return the relative folder path for a given epoch number.

    Epochs are hours since the Unix epoch (1970-01-01 00:00 UTC).
    Path format: epochs/YYYY/MM/DD/HH where HH is the hour (00-23).

    Examples:
        epoch_path(0) -> "epochs/1970/01/01/00"
        epoch_path(7) -> "epochs/1970/01/01/07"
        epoch_path(1717020000) -> "epochs/2024/05/30/12" (approx)

    Args:
        epoch: The epoch number (hours since Unix epoch).

    Returns:
        The relative path string for the epoch folder.
    """
    dt = datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(hours=epoch)
    return f"epochs/{dt.year:04d}/{dt.month:02d}/{dt.day:02d}/{dt.hour:02d}"


def epoch_of_path(path: str | Path) -> int:
    """Inverse of epoch_path: extract the epoch number from a folder path.

    Args:
        path: A path string or Path object like "epochs/1970/01/01/07"
              or "epochs/2024/05/30/12".

    Returns:
        The epoch number.

    Raises:
        ValueError: If the path doesn't match the expected format.
    """
    parts = Path(path).parts
    if len(parts) < 5 or parts[-5] != "epochs":
        raise ValueError(f"Invalid epoch path: {path}")
    try:
        year, month, day, hour = int(parts[-4]), int(parts[-3]), int(parts[-2]), int(parts[-1])
    except ValueError:
        raise ValueError(f"Invalid epoch path: {path}")
    dt = datetime(year, month, day, hour, tzinfo=timezone.utc)
    base = datetime(1970, 1, 1, tzinfo=timezone.utc)
    delta = dt - base
    epoch = int(delta.total_seconds() // 3600)
    if epoch < 0:
        raise ValueError(f"Epoch must be non-negative, got {epoch}")
    return epoch


def epoch_files(epoch: int, leaf_set: bytes, attestation: bytes) -> dict[str, bytes]:
    """Build all file contents for an epoch as a pure function.

    Args:
        epoch: The epoch number.
        leaf_set: The encoded leaf set bytes.
        attestation: The serialized attestation bytes.

    Returns:
        A dict mapping filenames to their content bytes.
    """
    from zeitwerk.epochtree import decode_leaf_set, build_epoch_tree

    leaves = decode_leaf_set(leaf_set)
    tree = build_epoch_tree(leaves)
    root = tree.root

    return {
        "leaves.bin": leaf_set,
        "leaves.hex": "\n".join(leaf.hex() for leaf in leaves).encode() + b"\n",
        "root": root,
        "attestation": attestation,
        "epoch.json": _epoch_json(epoch, len(leaves), root),
    }


def write_epoch(
    repo: Path,
    epoch: int,
    leaf_set: bytes,
    attestation: bytes,
) -> None:
    """Write all epoch files to the repository folder.

    Creates the epoch folder and writes:
        - leaves.bin: encoded leaf set (from encode_leaf_set)
        - leaves.hex: one hex leaf per line
        - root: 32-byte root hash (recomputed from leaf_set, not from attestation)
        - attestation: serialized attestation bytes
        - epoch.json: metadata with sorted keys for stable bytes

    Idempotent: if the folder already exists with the same bytes, does nothing.
    If the folder exists with *different* bytes, raises ValueError.

    Args:
        repo: Path to the repository root (where epochs/ and signers/ live).
        epoch: The epoch number.
        leaf_set: The frozen leaf set for this epoch (encoded bytes).
        attestation: The serialized attestation for this epoch.

    Raises:
        ValueError: If the epoch folder exists with different content.
    """
    epoch_folder = repo / epoch_path(epoch)
    epoch_folder.mkdir(parents=True, exist_ok=True)

    files = epoch_files(epoch, leaf_set, attestation)

    # Check idempotency: if folder exists, verify all files match
    for filename, content in files.items():
        filepath = epoch_folder / filename
        if filepath.exists():
            if filepath.read_bytes() != content:
                raise ValueError(
                    f"Epoch {epoch} folder exists with different {filename} content"
                )
        else:
            filepath.write_bytes(content)


def _epoch_json(epoch: int, leaf_count: int, root: bytes) -> bytes:
    """Build epoch.json content with sorted keys for stable bytes."""
    import json
    start = datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(hours=epoch)
    end = start + timedelta(hours=1)
    data = {
        "epoch": epoch,
        "interval": {"start": start.isoformat(), "end": end.isoformat()},
        "leaf_count": leaf_count,
        "root": root.hex(),
    }
    return json.dumps(data, sort_keys=True).encode()


def signer_metadata_json(valid_from: int | None, valid_until: int | None) -> bytes:
    """Build signer metadata JSON as a pure function.

    Args:
        valid_from: Unix timestamp when key becomes valid, or None.
        valid_until: Unix timestamp when key expires, or None.

    Returns:
        JSON bytes with sorted keys and trailing newline.
    """
    import json
    metadata = {
        "valid_from": valid_from,
        "valid_until": valid_until,
    }
    return json.dumps(metadata, sort_keys=True).encode() + b"\n"


def write_signer(repo: Path, public_key: bytes, valid_from: int | None = None, valid_until: int | None = None) -> bytes:
    """Write a signer's public key and metadata to the repository.

    Creates two files in signers/:
        - signers/<key_id>.pub: raw 32-byte Ed25519 public key
        - signers/<key_id>.json: {"valid_from": ..., "valid_until": ...}

    The key_id is the first 8 bytes of SHA-256(public_key).

    Args:
        repo: Path to the repository root.
        public_key: Raw 32-byte Ed25519 public key.
        valid_from: Unix timestamp (seconds) when this key becomes valid, or None.
        valid_until: Unix timestamp (seconds) when this key expires, or None.

    Returns:
        The key_id (8 bytes) used as the filename prefix.
    """
    from zeitwerk.signer import key_id_of

    key_id = key_id_of(public_key)
    signers_dir = repo / "signers"
    signers_dir.mkdir(parents=True, exist_ok=True)

    # Write .pub file
    pub_file = signers_dir / f"{key_id.hex()}.pub"
    pub_file.write_bytes(public_key)

    # Write .json file
    json_file = signers_dir / f"{key_id.hex()}.json"
    json_file.write_bytes(signer_metadata_json(valid_from, valid_until))

    return key_id


def read_epoch(repo: Path, epoch: int) -> tuple[bytes, bytes, bytes]:
    """Read epoch data from the repository folder.

    Returns the leaf set, root hash, and attestation bytes for the given epoch.

    Args:
        repo: Path to the repository root.
        epoch: The epoch number.

    Returns:
        A tuple of (leaf_set, root, attestation_bytes).

    Raises:
        FileNotFoundError: If the epoch folder or any required file is missing.
        ValueError: If the files are inconsistent (e.g., root doesn't match leaf_set).
    """
    from zeitwerk.epochtree import decode_leaf_set, build_epoch_tree

    epoch_folder = repo / epoch_path(epoch)

    leaf_set = (epoch_folder / "leaves.bin").read_bytes()
    root = (epoch_folder / "root").read_bytes()
    attestation = (epoch_folder / "attestation").read_bytes()

    # Verify consistency: root should match leaf_set
    leaves = decode_leaf_set(leaf_set)
    tree = build_epoch_tree(leaves)
    if tree.root != root:
        raise ValueError(
            f"Epoch {epoch}: stored root {root.hex()} doesn't match "
            f"leaf_set root {tree.root.hex()}"
        )

    return leaf_set, root, attestation


def verify_published(repo: Path, digest: bytes, epoch: int) -> bool:
    """Verify that a digest is included in a published epoch.

    This is the third-party check: using only the published folder and signers/,
    with no server or database, verify that:
        1. The digest is in the leaf set for the epoch
        2. The root matches the leaf set
        3. The attestation is valid (signed by a key in signers/)

    Args:
        repo: Path to the repository root.
        digest: The 32-byte fingerprint to verify.
        epoch: The epoch number to check.

    Returns:
        True if the digest is verified as included in the published epoch.

    Raises:
        FileNotFoundError: If the epoch is not published.
        ValueError: If verification fails, saying which check did.
    """
    from zeitwerk.attestation import AnchorType, ZeitwerkAttestation, deserialize_attestation
    from zeitwerk.epochtree import verify_inclusion
    from zeitwerk.signer import KEY_ID_SIZE, Signer

    # Reuse read_epoch to get leaf_set and root (which already verifies consistency)
    leaf_set, root, attestation = read_epoch(repo, epoch)

    # Verify inclusion
    if not verify_inclusion(digest, leaf_set, root):
        raise ValueError(f"Digest {digest.hex()} not in epoch {epoch} leaf set")

    # Verify the signature: the attestation names its signer by key_id, the
    # key is in signers/, and the signature covers this epoch and this root.
    att = deserialize_attestation(attestation)
    if type(att) is not ZeitwerkAttestation or att.anchor_type is not AnchorType.WITNESS_ED25519:
        raise ValueError(f"Epoch {epoch}: attestation is not a witness signature")
    if att.epoch != epoch:
        raise ValueError(f"Epoch {epoch}: attestation is for epoch {att.epoch}")
    key_id, signature = att.anchor_ref[:KEY_ID_SIZE], att.anchor_ref[KEY_ID_SIZE:]
    pub_file = repo / "signers" / f"{key_id.hex()}.pub"
    if not pub_file.exists():
        raise ValueError(f"Epoch {epoch}: signer {key_id.hex()} not in signers/")
    if not Signer.verify(pub_file.read_bytes(), epoch, root, signature):
        raise ValueError(f"Epoch {epoch}: signature by {key_id.hex()} does not verify")

    return True
