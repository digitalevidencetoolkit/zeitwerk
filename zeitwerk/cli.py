"""Command-line interface for zeitwerk verification.

This module provides a CLI wrapper around the zeitwerk verification functions.
It supports three modes:
1. verify --receipt --key: Check a receipt against a witness public key
2. recover: Rebuild a receipt from the public epoch repository
3. verify --epochs: Verify directly against the public record (operator offline)
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path


def parse_fingerprint(arg: str) -> bytes:
    """Parse a fingerprint argument: either a file path or a 64-hex string."""
    # Check if it's a hex string (64 characters, all hex digits)
    if len(arg) == 64 and all(c in "0123456789abcdefABCDEF" for c in arg):
        try:
            return bytes.fromhex(arg)
        except ValueError:
            pass

    # Otherwise, treat it as a file path
    path = Path(arg)
    if not path.exists():
        print(f"Error: File not found: {arg}", file=sys.stderr)
        sys.exit(2)

    # Hash the file content
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            h.update(chunk)
    return h.digest()


def find_epoch_for_digest(repo: Path, digest: bytes) -> int | None:
    """Search the repository for an epoch containing the digest.

    Greps the leaf lists (leaves.hex files) for the hex fingerprint.
    Returns the epoch number if found, None otherwise.
    """
    from zeitwerk.publisher import epoch_of_path

    hex_digest = digest.hex()

    # Walk the epochs directory
    epochs_dir = repo / "epochs"
    if not epochs_dir.exists():
        return None

    for year_dir in epochs_dir.iterdir():
        if not year_dir.is_dir():
            continue
        for month_dir in year_dir.iterdir():
            if not month_dir.is_dir():
                continue
            for day_dir in month_dir.iterdir():
                if not day_dir.is_dir():
                    continue
                for hour_dir in day_dir.iterdir():
                    if not hour_dir.is_dir():
                        continue

                    # Check if this hour directory has the digest
                    leaves_hex = hour_dir / "leaves.hex"
                    if leaves_hex.exists():
                        try:
                            content = leaves_hex.read_text()
                            if hex_digest in content:
                                return epoch_of_path(hour_dir)
                        except (IOError, UnicodeDecodeError):
                            continue

    return None


def cmd_recover(args: argparse.Namespace) -> int:
    """Recover a receipt from the public epoch repository.
    
    This is the "I lost the receipt" mode: rebuild it from the published
    record and output to stdout.
    
    Returns exit code: 0=success, 1=not found, 2=bad input
    """
    from zeitwerk.publisher import read_epoch
    from zeitwerk.epochtree import recover_receipt
    from zeitwerk.attestation import deserialize_attestation
    
    digest = parse_fingerprint(args.file)
    repo = Path(args.epochs)
    
    if not repo.exists():
        print(f"Error: Repository not found: {args.epochs}", file=sys.stderr)
        return 2
    
    # Find the epoch containing this digest
    epoch = find_epoch_for_digest(repo, digest)
    if epoch is None:
        print(f"Error: No epoch found containing fingerprint {digest.hex()}", file=sys.stderr)
        return 1
    
    try:
        # Read epoch data
        leaf_set, root, attestation_bytes = read_epoch(repo, epoch)
        # Deserialize the attestation
        attestation = deserialize_attestation(attestation_bytes)
        # Recover the receipt
        receipt = recover_receipt(digest, leaf_set, attestation)
        # Output to stdout
        sys.stdout.buffer.write(receipt)
        return 0
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2


def cmd_verify_epochs(args: argparse.Namespace) -> int:
    """Verify a document against the public epoch repository.

    This is the "I trust nobody" mode: verify directly from the published
    record with the operator offline.

    Returns exit code: 0=verified, 1=not verified, 2=bad input
    """
    from zeitwerk.publisher import verify_published, epoch_start
    from zeitwerk.epochtree import verify_non_inclusion, decode_leaf_set, build_epoch_tree

    digest = parse_fingerprint(args.file)
    repo = Path(args.epochs)

    if not repo.exists():
        print(f"Error: Repository not found: {args.epochs}", file=sys.stderr)
        return 2

    # If epoch is specified, use it directly
    if args.epoch is not None:
        epoch = args.epoch
    else:
        # Search for the epoch containing this digest
        epoch = find_epoch_for_digest(repo, digest)
        if epoch is None:
            print(f"Error: No epoch found containing fingerprint {digest.hex()}", file=sys.stderr)
            return 1

    try:
        # Try to verify inclusion
        verify_published(repo, digest, epoch)

        # If we get here, verification passed
        # Print the verification story
        from zeitwerk.publisher import read_epoch
        from zeitwerk.attestation import deserialize_attestation, AnchorType, ZeitwerkAttestation
        from zeitwerk.signer import key_id_of, KEY_ID_SIZE

        leaf_set, root, attestation = read_epoch(repo, epoch)
        leaves = decode_leaf_set(leaf_set)

        print(f"fingerprint  {digest.hex()}")
        start = epoch_start(epoch)
        print(f"hour         {epoch} = {start.strftime('%Y-%m-%d %H:00 UTC')}")
        print(f"leaf set     {len(leaves)} fingerprints, root {root.hex()} matches")

        att = deserialize_attestation(attestation)
        if isinstance(att, ZeitwerkAttestation) and att.anchor_type == AnchorType.WITNESS_ED25519:
            key_id = att.anchor_ref[:KEY_ID_SIZE]
            print(f"signer       {key_id.hex()}")

        print("VERIFIED     signature valid over (hour, root)")
        return 0

    except ValueError as e:
        error_msg = str(e)

        # Check if it's a non-inclusion error
        if "not in epoch" in error_msg and "leaf set" in error_msg:
            # Explicit non-inclusion proof
            try:
                from zeitwerk.publisher import read_epoch
                leaf_set, root, _ = read_epoch(repo, epoch)
                leaves = decode_leaf_set(leaf_set)
                tree = build_epoch_tree(leaves)

                if tree.root == root and digest not in set(leaves):
                    start = epoch_start(epoch)
                    print(f"fingerprint  {digest.hex()}", file=sys.stderr)
                    print(f"hour         {epoch} = {start.strftime('%Y-%m-%d %H:00 UTC')}", file=sys.stderr)
                    print(f"leaf set     {len(leaves)} fingerprints, root {root.hex()} matches", file=sys.stderr)
                    print(f"NOT VERIFIED fingerprint not in leaf set", file=sys.stderr)
                    return 1
            except Exception:
                pass

        # For other errors, just print the error
        print(f"NOT VERIFIED {error_msg}", file=sys.stderr)
        return 1

    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2


def main(argv: list[str] | None = None) -> int:
    """Main entry point for the zeitwerk CLI.

    Returns exit code: 0=success, 1=verification failed, 2=bad input
    """
    parser = argparse.ArgumentParser(
        prog="zeitwerk",
        description="Verify documents against Zeitwerk timestamping"
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # verify command
    verify_parser = subparsers.add_parser("verify", help="Verify a document")
    verify_parser.add_argument(
        "file",
        help="File to verify or 64-hex fingerprint"
    )
    verify_parser.add_argument(
        "--epochs",
        metavar="REPO",
        help="Path to the published epochs repository"
    )
    verify_parser.add_argument(
        "--epoch",
        type=int,
        metavar="N",
        help="Specific epoch to check (otherwise searches all epochs)"
    )
    verify_parser.add_argument(
        "--receipt",
        metavar="FILE",
        help="Path to the receipt file"
    )
    verify_parser.add_argument(
        "--key",
        metavar="FILE",
        help="Path to the witness public key file"
    )

    # recover command
    recover_parser = subparsers.add_parser("recover", help="Recover a receipt from the public record")
    recover_parser.add_argument(
        "file",
        help="File to recover or 64-hex fingerprint"
    )
    recover_parser.add_argument(
        "--epochs",
        metavar="REPO",
        required=True,
        help="Path to the published epochs repository"
    )

    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return 2

    if args.command == "verify":
        if args.epochs:
            return cmd_verify_epochs(args)
        elif args.receipt and args.key:
            print("Error: verify --receipt --key not yet implemented", file=sys.stderr)
            return 2
        else:
            print("Error: Must specify either --epochs or --receipt --key", file=sys.stderr)
            return 2
    
    elif args.command == "recover":
        return cmd_recover(args)

    else:
        print(f"Error: Unknown command: {args.command}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
