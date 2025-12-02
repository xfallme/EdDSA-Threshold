from abc import ABC, abstractmethod


class Keypair(ABC):

    def __init__(self, seed: bytes, scalar: int, public_bytes: bytes):
        self._private_bytes = seed
        self._scalar = scalar
        self._public_bytes = public_bytes

    # Access to Keypair components
    def private_bytes(self) -> bytes:
        return self._private_bytes  # type: ignore

    def scalar(self) -> int:
        return self._scalar  # type: ignore

    def public_bytes(self) -> bytes:
        return self._public_bytes  # type: ignore

    # Generate Keypair
    @classmethod
    @abstractmethod
    def from_private_bytes(cls, seed: bytes) -> Keypair: ...

    @classmethod
    @abstractmethod
    def generate(cls) -> Keypair: ...
