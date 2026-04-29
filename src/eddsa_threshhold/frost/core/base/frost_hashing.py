from abc import ABC, abstractmethod


class FrostHashing(ABC):
    """
    FrostHashing is the base class that ensures that all hashing functions used in the FROST protocol are present.
    """

    @abstractmethod
    def h1(self, m: bytes) -> int:
        raise NotImplementedError()

    @abstractmethod
    def h2(self, m: bytes) -> int:
        raise NotImplementedError()

    @abstractmethod
    def h3(self, m: bytes) -> int:
        raise NotImplementedError()

    @abstractmethod
    def h4(self, m: bytes) -> bytes:
        raise NotImplementedError()

    @abstractmethod
    def h5(self, m: bytes) -> bytes:
        raise NotImplementedError()
