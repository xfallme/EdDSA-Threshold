from abc import ABC, abstractmethod

from eddsa.keys.keypair import Keypair


class EdDSA(ABC):
    """
    Abstract base class for EdDSA signature algorithms.
    Defines abstract methods for signing and verifying messages.
    """

    @staticmethod
    @abstractmethod
    def sign(message: bytes, keypair: Keypair) -> bytes:
        """Sign a message using the provided keypair."""
        raise NotImplementedError

    @staticmethod
    @abstractmethod
    def verify(signature: bytes, message: bytes, public_key: bytes) -> bool:
        """Verify a signature for a message using the provided public key."""
        raise NotImplementedError
