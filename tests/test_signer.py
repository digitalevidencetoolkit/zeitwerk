"""Tests for the Ed25519 signer (issue #17)."""

import unittest

from zeitwerk.signer import Signer


class SignerTests(unittest.TestCase):
    def test_ephemeral_signer_roundtrip(self):
        """Generate, sign, verify with ephemeral keys."""
        signer = Signer()
        epoch = 42
        root = b"\x00" * 32
        sig = signer.sign(epoch, root)
        self.assertTrue(
            Signer.verify(
                signer.public_key, epoch, root, signer.key_id, sig
            )
        )

    def test_wrong_epoch_fails(self):
        """Signature with wrong epoch does not verify."""
        signer = Signer()
        root = b"\x00" * 32
        sig = signer.sign(42, root)
        self.assertFalse(
            Signer.verify(
                signer.public_key, 43, root, signer.key_id, sig
            )
        )

    def test_wrong_root_fails(self):
        """Signature with wrong root does not verify."""
        signer = Signer()
        sig = signer.sign(42, b"\x00" * 32)
        self.assertFalse(
            Signer.verify(
                signer.public_key, 42, b"\x01" * 32, signer.key_id, sig
            )
        )

    def test_wrong_key_fails(self):
        """Signature verified with wrong public key fails."""
        signer1 = Signer()
        signer2 = Signer()
        sig = signer1.sign(42, b"\x00" * 32)
        self.assertFalse(
            Signer.verify(
                signer2.public_key, 42, b"\x00" * 32, signer1.key_id, sig
            )
        )

    def test_misused_verify_raises(self):
        """A caller bug (no signature at all) raises, rather than reading as a bad signature."""
        signer = Signer()
        with self.assertRaises(TypeError):
            Signer.verify(signer.public_key, 42, b"\x00" * 32, signer.key_id, None)

    def test_key_id_is_first_8_sha256_bytes(self):
        """key_id is first 8 bytes of SHA-256(public_key)."""
        import hashlib

        signer = Signer()
        expected = hashlib.sha256(signer.public_key).digest()[:8]
        self.assertEqual(signer.key_id, expected)

    def test_public_key_is_32_bytes(self):
        """Ed25519 public keys are 32 bytes."""
        signer = Signer()
        self.assertEqual(len(signer.public_key), 32)

    def test_key_id_is_8_bytes(self):
        """key_id is 8 bytes."""
        signer = Signer()
        self.assertEqual(len(signer.key_id), 8)

    def test_key_file_survives_restart(self):
        """A key written on first run is loaded back, so old signatures still verify."""
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:
            key_path = Path(tmp) / "witness.pem"
            sig = Signer(key_path).sign(42, b"\x00" * 32)
            restarted = Signer(key_path)
            self.assertTrue(
                Signer.verify(
                    restarted.public_key, 42, b"\x00" * 32, restarted.key_id, sig
                )
            )


if __name__ == "__main__":
    unittest.main()
