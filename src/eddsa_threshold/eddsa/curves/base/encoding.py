from abc import ABC, abstractmethod
from typing import Tuple

from eddsa_threshold.eddsa.curves.base.field_ops import FieldOps


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
    def group_order(self) -> int:
        """Group order of the field."""
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

    def encode_scalar(self, x: int) -> bytes:
        """Serialize a scalar to bytes (little-endian)."""
        return x.to_bytes(self.scalar_size, byteorder='little')
    
    def decode_scalar(self, data: bytes) -> int:
        """Deserialize bytes to a scalar (little-endian)."""
        if len(data) != self.scalar_size:
            raise ValueError(f"Invalid scalar size: expected {self.scalar_size} bytes")
        value = int.from_bytes(data, byteorder='little')
        if value < 0 or value >= self.group_order:
            raise ValueError("Deserialized scalar is out of range")
        return value