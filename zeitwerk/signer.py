"""Ed25519 signer for zeitwerk epoch roots (issue #17)."""

from __future__ import annotations

import hashlib
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
)

V0_PREFIX = b"zeitwerk-v0"
KEY_ID_SIZE = 8


def key_id_of(public_key: bytes) -> bytes:
    """First 8 bytes of SHA-256(public_key)."""
    return hashlib.sha256(public_key).digest()[:KEY_ID_SIZE]


def _message(epoch: int, root: bytes, key_id: bytes) -> bytes:
    """What gets signed: b'zeitwerk-v0' + epoch (8 bytes) + root + key_id."""
    epoch_bytes = epoch.to_bytes(8, "big")
    return V0_PREFIX + epoch_bytes + root + key_id


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
                key_path.touch(mode=0o600, exist_ok=False)  # private before the key goes in
                key_path.write_bytes(
                    self._private_key.private_bytes(
                        Encoding.PEM,
                        PrivateFormat.PKCS8,
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
        return key_id_of(self.public_key)

    def sign(self, epoch: int, root: bytes) -> bytes:
        """Sign an epoch root (see _message)."""
        return self._private_key.sign(_message(epoch, root, self.key_id))

    @staticmethod
    def verify(public_key: bytes, epoch: int, root: bytes, signature: bytes) -> bool:
        """Verify a v0 signature. public_key must be 32 raw bytes."""
        pk = Ed25519PublicKey.from_public_bytes(public_key)
        try:
            pk.verify(signature, _message(epoch, root, key_id_of(public_key)))
            return True
        except InvalidSignature:
            return False
