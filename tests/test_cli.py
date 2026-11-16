"""Tests for zeitwerk.cli — command-line interface.
"""

import tempfile
import unittest
from pathlib import Path

import zeitwerk  # noqa: F401  (runs the python-opentimestamps path shim)
from zeitwerk.cli import main, parse_fingerprint, find_epoch_for_digest


class ParseFingerprintTests(unittest.TestCase):
    """Tests for parse_fingerprint."""

    def test_hex_string(self):
        """A 64-hex string is parsed as a fingerprint – could be anything"""
        digest = parse_fingerprint("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
        self.assertEqual(len(digest), 32)
        self.assertEqual(
            digest.hex(),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        )

    def test_file_path(self):
        """A file path is hashed to produce a fingerprint"""
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
            f.write("hello world")
            f.flush()
            temp_path = f.name

        try:
            import hashlib
            expected = hashlib.sha256(b"hello world").digest()
            digest = parse_fingerprint(temp_path)
            self.assertEqual(digest, expected)
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_file_not_found(self):
        with self.assertRaises(SystemExit) as ctx:
            parse_fingerprint("/nonexistent/file.txt")
        self.assertEqual(ctx.exception.code, 2)


class FindEpochForDigestTests(unittest.TestCase):
    """Tests for find_epoch_for_digest."""

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp())

    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_find_epoch_with_digest(self):
        """Finds an epoch containing a specific digest."""
        import hashlib
        from zeitwerk.publisher import write_epoch, epoch_path
        from zeitwerk.epochtree import build_epoch_tree, encode_leaf_set

        # Create some digests
        digests = [
            hashlib.sha256(b"document1").digest(),
            hashlib.sha256(b"document2").digest(),
            hashlib.sha256(b"document3").digest(),
        ]

        # Write epoch 42
        tree = build_epoch_tree(digests)
        leaf_set = encode_leaf_set(tree.leaves)
        write_epoch(self.temp_dir, 42, leaf_set, b"test_attestation")

        # Search for the first digest
        found_epoch = find_epoch_for_digest(self.temp_dir, digests[0])
        self.assertEqual(found_epoch, 42)

        # Search for a digest not in the epoch
        other_digest = hashlib.sha256(b"other").digest()
        found_epoch = find_epoch_for_digest(self.temp_dir, other_digest)
        self.assertIsNone(found_epoch)

    def test_digest_in_several_epochs_returns_earliest(self):
        """A document submitted in several epochs is timestamped by the earliest."""
        import hashlib
        from zeitwerk.publisher import write_epoch
        from zeitwerk.epochtree import encode_leaf_set

        digest = hashlib.sha256(b"document1").digest()
        # Written newest first, so creation order isn't chronological order.
        for epoch in (480_000, 250_000, 7):
            write_epoch(self.temp_dir, epoch, encode_leaf_set([digest]), b"test_attestation")

        self.assertEqual(find_epoch_for_digest(self.temp_dir, digest), 7)

    def test_no_epochs_folder(self):
        """A repository with no epochs/ folder has nothing to find."""
        import hashlib

        digest = hashlib.sha256(b"document1").digest()
        self.assertIsNone(find_epoch_for_digest(self.temp_dir, digest))


class VerifyEpochsTests(unittest.TestCase):
    """Tests for the verify --epochs command."""

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp())

    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _create_test_epoch(self, epoch_num: int, digests: list[bytes], signer_key: bytes | None = None):
        """Helper to create a test epoch with signed attestation."""
        from zeitwerk.epochtree import build_epoch_tree, encode_leaf_set
        from zeitwerk.publisher import write_epoch, write_signer
        from zeitwerk.attestation import AnchorType, ZeitwerkAttestation, serialize_attestation
        from zeitwerk.signer import Signer, key_id_of

        tree = build_epoch_tree(digests)
        leaf_set = encode_leaf_set(tree.leaves)

        if signer_key is None:
            # Create a new signer
            signer = Signer()
            write_signer(self.temp_dir, signer.public_key)
            signature = signer.sign(epoch_num, tree.root)
            key_id = signer.key_id
        else:
            # Use provided key
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

            pk = Ed25519PublicKey.from_public_bytes(signer_key)
            key_id = key_id_of(signer_key)
            write_signer(self.temp_dir, signer_key)

            # Create signature
            from zeitwerk.signer import _message
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
            from cryptography.hazmat.primitives.serialization import PrivateFormat, NoEncryption

            # For testing, we need to create a signature. Since we only have the public key,
            # we'll use a placeholder. In real tests, we'd need the private key.
            # For now, let's just use a new signer
            signer = Signer()
            write_signer(self.temp_dir, signer.public_key)
            signature = signer.sign(epoch_num, tree.root)
            key_id = signer.key_id

        # Create attestation
        anchor_ref = key_id + signature
        att = ZeitwerkAttestation(
            epoch=epoch_num,
            anchor_type=AnchorType.WITNESS_ED25519,
            anchor_ref=anchor_ref
        )
        attestation = serialize_attestation(att)

        write_epoch(self.temp_dir, epoch_num, leaf_set, attestation)
        return tree.root, key_id

    def test_verify_included_digest(self):
        """Verify a digest that is included in an epoch."""
        import hashlib

        digests = [
            hashlib.sha256(b"document1").digest(),
            hashlib.sha256(b"document2").digest(),
        ]
        self._create_test_epoch(42, digests)

        # Create a temp file with content that hashes to one of the digests
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
            f.write("document1")
            f.flush()
            temp_path = f.name

        try:
            # Run verify command
            result = main(["verify", temp_path, "--epochs", str(self.temp_dir), "--epoch", "42"])
            self.assertEqual(result, 0)
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_verify_hex_fingerprint(self):
        """Verify using a hex fingerprint directly."""
        import hashlib

        digests = [hashlib.sha256(b"document1").digest()]
        self._create_test_epoch(42, digests)

        fingerprint = digests[0].hex()
        result = main(["verify", fingerprint, "--epochs", str(self.temp_dir), "--epoch", "42"])
        self.assertEqual(result, 0)

    def test_verify_not_included_digest(self):
        """Verify a digest that is NOT included in an epoch."""
        import hashlib

        digests = [hashlib.sha256(b"document1").digest()]
        self._create_test_epoch(42, digests)

        # Try to verify a different digest
        other_digest = hashlib.sha256(b"other").digest().hex()
        result = main(["verify", other_digest, "--epochs", str(self.temp_dir), "--epoch", "42"])
        self.assertEqual(result, 1)

    def test_verify_search_epoch(self):
        """Verify without specifying epoch - should search all epochs."""
        import hashlib

        digests = [hashlib.sha256(b"document1").digest()]
        self._create_test_epoch(42, digests)

        fingerprint = digests[0].hex()
        result = main(["verify", fingerprint, "--epochs", str(self.temp_dir)])
        self.assertEqual(result, 0)

    def test_verify_repo_not_found(self):
        """Verify with non-existent repository."""
        import hashlib

        fingerprint = hashlib.sha256(b"test").digest().hex()
        result = main(["verify", fingerprint, "--epochs", "/nonexistent/repo"])
        self.assertEqual(result, 2)


class RecoverTests(unittest.TestCase):
    """Tests for the recover command."""

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp())

    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _create_test_epoch(self, epoch_num: int, digests: list[bytes]):
        """Helper to create a test epoch with signed attestation."""
        from zeitwerk.epochtree import build_epoch_tree, encode_leaf_set
        from zeitwerk.publisher import write_epoch, write_signer
        from zeitwerk.attestation import AnchorType, ZeitwerkAttestation, serialize_attestation
        from zeitwerk.signer import Signer
        
        tree = build_epoch_tree(digests)
        leaf_set = encode_leaf_set(tree.leaves)
        
        # Create a signer
        signer = Signer()
        write_signer(self.temp_dir, signer.public_key)
        
        # Create attestation
        signature = signer.sign(epoch_num, tree.root)
        key_id = signer.key_id
        anchor_ref = key_id + signature
        att = ZeitwerkAttestation(
            epoch=epoch_num,
            anchor_type=AnchorType.WITNESS_ED25519,
            anchor_ref=anchor_ref
        )
        attestation = serialize_attestation(att)
        
        write_epoch(self.temp_dir, epoch_num, leaf_set, attestation)
        return tree.root, key_id, leaf_set, attestation

    def test_recover_known_digest(self):
        """Recover a receipt for a known digest."""
        import hashlib
        from zeitwerk.epochtree import recover_receipt
        from zeitwerk.attestation import deserialize_attestation
        from io import BytesIO
        import sys
        
        digests = [hashlib.sha256(b"document1").digest()]
        _, _, leaf_set, attestation_bytes = self._create_test_epoch(42, digests)
        
        # Get expected receipt using library directly
        # recover_receipt expects deserialized attestation objects
        attestation = deserialize_attestation(attestation_bytes)
        expected_receipt = recover_receipt(digests[0], leaf_set, attestation)
        
        # Capture stdout from CLI
        old_stdout = sys.stdout
        sys.stdout = BytesIO()
        # Also need to set buffer attribute for sys.stdout.buffer access
        sys.stdout.buffer = sys.stdout
        try:
            fingerprint = digests[0].hex()
            result = main(["recover", fingerprint, "--epochs", str(self.temp_dir)])
            output = sys.stdout.getvalue()
        finally:
            sys.stdout = old_stdout
        
        self.assertEqual(result, 0)
        self.assertEqual(output, expected_receipt)

    def test_recover_unknown_digest(self):
        """Recover for an unknown digest exits 1 with clear error."""
        import hashlib
        
        digests = [hashlib.sha256(b"document1").digest()]
        self._create_test_epoch(42, digests)
        
        # Try to recover a different digest
        other_digest = hashlib.sha256(b"other").hexdigest()
        result = main(["recover", other_digest, "--epochs", str(self.temp_dir)])
        self.assertEqual(result, 1)

    def test_recover_file_path(self):
        """Recover using a file path instead of hex fingerprint."""
        import hashlib
        from zeitwerk.epochtree import recover_receipt
        from zeitwerk.attestation import deserialize_attestation
        from io import BytesIO
        import sys
        
        digests = [hashlib.sha256(b"document1").digest()]
        _, _, leaf_set, attestation_bytes = self._create_test_epoch(42, digests)
        
        # Create a temp file
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
            f.write("document1")
            f.flush()
            temp_path = f.name
        
        try:
            # Get expected receipt using library directly
            attestation = deserialize_attestation(attestation_bytes)
            expected_receipt = recover_receipt(digests[0], leaf_set, attestation)
            
            # Capture stdout from CLI
            old_stdout = sys.stdout
            sys.stdout = BytesIO()
            sys.stdout.buffer = sys.stdout
            try:
                result = main(["recover", temp_path, "--epochs", str(self.temp_dir)])
                output = sys.stdout.getvalue()
            finally:
                sys.stdout = old_stdout
            
            self.assertEqual(result, 0)
            self.assertEqual(output, expected_receipt)
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_recover_repo_not_found(self):
        """Recover with non-existent repository."""
        import hashlib
        
        fingerprint = hashlib.sha256(b"test").hexdigest()
        result = main(["recover", fingerprint, "--epochs", "/nonexistent/repo"])
        self.assertEqual(result, 2)


class VerifyReceiptTests(unittest.TestCase):
    """Tests for verify --receipt --key command."""

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp())

    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _create_signed_tree(self, digests, epoch=42):
        """Helper to create a tree with a signed attestation."""
        from zeitwerk.epochtree import build_epoch_tree
        from zeitwerk.witness import signed_attestation
        from zeitwerk.signer import Signer
        
        signer = Signer()
        tree = build_epoch_tree(digests)
        tree.tip.attestations.add(signed_attestation(signer, epoch, tree.root))
        return tree, signer

    def test_good_receipt_with_correct_key(self):
        """Verify a valid receipt with the correct public key."""
        import hashlib
        
        digests = [hashlib.sha256(b"document1").digest()]
        tree, signer = self._create_signed_tree(digests)
        receipt = tree.receipt_bytes(digests[0])
        
        # Write receipt and key to temp files
        receipt_file = self.temp_dir / "receipt.ots"
        key_file = self.temp_dir / "key.pub"
        receipt_file.write_bytes(receipt)
        key_file.write_bytes(signer.public_key)
        
        fingerprint = digests[0].hex()
        result = main(["verify", fingerprint, "--receipt", str(receipt_file), "--key", str(key_file)])
        self.assertEqual(result, 0)

    def test_good_receipt_with_wrong_key(self):
        """Verify a valid receipt with a different public key."""
        import hashlib
        from zeitwerk.signer import Signer
        
        digests = [hashlib.sha256(b"document1").digest()]
        tree, _ = self._create_signed_tree(digests)
        receipt = tree.receipt_bytes(digests[0])
        
        # Write receipt and a different key to temp files
        receipt_file = self.temp_dir / "receipt.ots"
        key_file = self.temp_dir / "key.pub"
        receipt_file.write_bytes(receipt)
        
        # Use a different signer's key
        wrong_signer = Signer()
        key_file.write_bytes(wrong_signer.public_key)
        
        fingerprint = digests[0].hex()
        result = main(["verify", fingerprint, "--receipt", str(receipt_file), "--key", str(key_file)])
        self.assertEqual(result, 1)

    def test_tampered_receipt(self):
        """Verify a tampered/modified receipt."""
        import hashlib
        
        digests = [hashlib.sha256(b"document1").digest()]
        tree, signer = self._create_signed_tree(digests)
        receipt = tree.receipt_bytes(digests[0])
        
        # Tamper with the receipt (flip a bit)
        tampered_receipt = bytearray(receipt)
        if len(tampered_receipt) > 0:
            tampered_receipt[0] ^= 0xFF  # Flip all bits in first byte
        
        # Write tampered receipt and key to temp files
        receipt_file = self.temp_dir / "receipt.ots"
        key_file = self.temp_dir / "key.pub"
        receipt_file.write_bytes(bytes(tampered_receipt))
        key_file.write_bytes(signer.public_key)
        
        fingerprint = digests[0].hex()
        result = main(["verify", fingerprint, "--receipt", str(receipt_file), "--key", str(key_file)])
        self.assertEqual(result, 1)

    def test_fingerprint_absent_from_receipt(self):
        """Verify with a fingerprint that doesn't match the receipt."""
        import hashlib
        
        digests = [
            hashlib.sha256(b"document1").digest(),
            hashlib.sha256(b"document2").digest(),
        ]
        tree, signer = self._create_signed_tree(digests)
        # Get receipt for first digest
        receipt = tree.receipt_bytes(digests[0])
        
        # Write receipt and key to temp files
        receipt_file = self.temp_dir / "receipt.ots"
        key_file = self.temp_dir / "key.pub"
        receipt_file.write_bytes(receipt)
        key_file.write_bytes(signer.public_key)
        
        # Try to verify with the second digest (not in this receipt)
        fingerprint = digests[1].hex()
        result = main(["verify", fingerprint, "--receipt", str(receipt_file), "--key", str(key_file)])
        self.assertEqual(result, 1)


class FixtureTests(unittest.TestCase):
    """Tests using the fixture data from a real epoch."""

    def test_verify_with_fixture_epoch(self):
        """Verify a document using the fixture epoch 498469."""
        from pathlib import Path
        
        fixtures_dir = Path(__file__).parent.parent / "fixtures"
        
        # Check if fixtures exist
        epoch_dir = fixtures_dir / "epochs" / "2026" / "11" / "12" / "13"
        if not epoch_dir.exists():
            self.skipTest("Fixture epoch 498469 not found")
        
        # Read the leaf set to get a valid fingerprint
        leaves_hex = epoch_dir / "leaves.hex"
        if not leaves_hex.exists():
            self.skipTest("Fixture leaves.hex not found")
        
        content = leaves_hex.read_text()
        fingerprints = [line.strip() for line in content.strip().split("\n") if line.strip()]
        
        if not fingerprints:
            self.skipTest("No fingerprints in fixture")
        
        # Use the first fingerprint
        fingerprint = fingerprints[0]
        
        # Verify using the fixture repo
        result = main(["verify", fingerprint, "--epochs", str(fixtures_dir), "--epoch", "498469"])
        self.assertEqual(result, 0)

    def test_recover_with_fixture_epoch(self):
        """Recover a receipt using the fixture epoch 498469."""
        from pathlib import Path
        
        fixtures_dir = Path(__file__).parent.parent / "fixtures"
        
        # Check if fixtures exist
        epoch_dir = fixtures_dir / "epochs" / "2026" / "11" / "12" / "13"
        if not epoch_dir.exists():
            self.skipTest("Fixture epoch 498469 not found")
        
        # Read the leaf set to get a valid fingerprint
        leaves_hex = epoch_dir / "leaves.hex"
        if not leaves_hex.exists():
            self.skipTest("Fixture leaves.hex not found")
        
        content = leaves_hex.read_text()
        fingerprints = [line.strip() for line in content.strip().split("\n") if line.strip()]
        
        if not fingerprints:
            self.skipTest("No fingerprints in fixture")
        
        # Use the first fingerprint
        fingerprint = fingerprints[0]
        
        # Recover the receipt
        result = main(["recover", fingerprint, "--epochs", str(fixtures_dir)])
        self.assertEqual(result, 0)


class MainTests(unittest.TestCase):
    """Tests for main() argument parsing."""

    def test_no_command(self):
        """No command provided - should print help and exit."""
        result = main([])
        self.assertEqual(result, 2)

    def test_verify_no_args(self):
        """Verify without required arguments."""
        with self.assertRaises(SystemExit) as ctx:
            main(["verify"])
        self.assertEqual(ctx.exception.code, 2)

    def test_recover_no_epochs(self):
        """Recover without --epochs should fail."""
        with self.assertRaises(SystemExit) as ctx:
            main(["recover", "test.txt"])
        self.assertEqual(ctx.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
