from abc import ABC, abstractmethod


class Keypair(ABC):
    """
    Abstract base class for EdDSA keypairs.
    Provides access to private seed, scalar, and public key bytes.

    Also defines abstract methods for keypair generation.
    These allow for keypair creation from a private seed or generation of a fresh random keypair.
    """

    def __init__(self, seed: bytes, scalar: int, public_bytes: bytes):
        """Initialize Keypair with private seed, scalar, and public key bytes."""
        self._private_bytes = seed
        self._scalar = scalar
        self._public_bytes = public_bytes

    def private_bytes(self) -> bytes:
        """Return the private seed bytes used to generate the keypair."""
        return self._private_bytes

    def scalar(self) -> int:
        """Return the integer scalar derived from the private seed."""
        return self._scalar

    def public_bytes(self) -> bytes:
        """Return the public key bytes corresponding to the keypair."""
        return self._public_bytes

    @classmethod
    @abstractmethod
    def from_private_bytes(cls, seed: bytes) -> Keypair: ...

    @classmethod
    @abstractmethod
    def generate(cls) -> Keypair: ...
