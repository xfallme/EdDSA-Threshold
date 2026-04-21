from abc import ABC, abstractmethod
from typing import Tuple

from eddsa_threshhold.eddsa.curves.base.field_ops import FieldOps


class Encoding(ABC):
    """
    Abstract byte encoding/decoding layer.
    """

    @abstractmethod
    def __init__(self, FieldOps: FieldOps):
        """Initialize with field operations."""
        raise NotImplementedError

    @property
    @abstractmethod
    def scalar_size(self) -> int:
        """Size in bytes of a private scalar."""
        raise NotImplementedError

    @property
    @abstractmethod
    def point_size(self) -> int:
        """Size in bytes of an encoded public key point."""
        raise NotImplementedError

    @abstractmethod
    def encode_point(self, P: Tuple) -> bytes:
        raise NotImplementedError

    @abstractmethod
    def decode_point(self, data: bytes) -> Tuple:
        raise NotImplementedError
