"""Ed25519 signer for zeitwerk epoch roots (issue #17)."""

from __future__ import annotations

import hashlib
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PublicFormat,
    load_pem_private_key,
)

V0_PREFIX = b"zeitwerk-v0"


class Signer:
    """Single Ed25519 signer for epoch roots.

    Generates or loads a keypair, signs epoch roots, and verifies signatures.
    """

    def __init__(self, key_path: str | Path | None = None):
        if key_path is None:
            self._private_key = Ed25519PrivateKey.generate()
        else:
            key_path = Path(key_path)
            if key_path.exists():
                self._private_key = load_pem_private_key(
                    key_path.read_bytes(), password=None
                )
            else:
                self._private_key = Ed25519PrivateKey.generate()
                key_path.write_bytes(
                    self._private_key.private_bytes(
                        Encoding.PEM,
                        PublicFormat.PKCS8,
                        NoEncryption(),
                    )
                )

    @property
    def public_key(self) -> bytes:
        """Raw Ed25519 public key (32 bytes)."""
        return self._private_key.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )

    @property
    def key_id(self) -> bytes:
        """First 8 bytes of SHA-256(public_key)."""
        return hashlib.sha256(self.public_key).digest()[:8]

    def sign(self, epoch: int, root: bytes) -> bytes:
        """Sign an epoch root: b'zeitwerk-v0' + epoch + root + key_id."""
        message = V0_PREFIX + epoch.to_bytes(8, "big") + root + self.key_id
        return self._private_key.sign(message)

    @staticmethod
    def verify(
        public_key: bytes, epoch: int, root: bytes, key_id: bytes, signature: bytes
    ) -> bool:
        """Verify a v0 signature. public_key must be 32 raw bytes."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey,
        )

        pk = Ed25519PublicKey.from_public_bytes(public_key)
        message = V0_PREFIX + epoch.to_bytes(8, "big") + root + key_id
        try:
            pk.verify(signature, message)
            return True
        except Exception:
            return False
