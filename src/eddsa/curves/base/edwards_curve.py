from abc import ABC, abstractmethod
from typing import Tuple


class EdwardsCurve(ABC):
    @property
    @abstractmethod
    def field(self):
        """Return the FieldOps implementation."""
        raise NotImplementedError

    @property
    @abstractmethod
    def encoding(self):
        """Return the Encoding implementation."""
        raise NotImplementedError

    @property
    @abstractmethod
    def base_point(self):
        """Return affine base point as (x, y)."""
        raise NotImplementedError

    # Encode and decode points

    def encode_extended_point(self, P: Tuple) -> bytes:
        """Encode point from (X, Y, Z, T) to bytes."""
        return self.encode_affine_point(self.extended_to_affine(P))

    def encode_affine_point(self, P: Tuple) -> bytes:
        """Encode point from (x, y) to bytes."""
        return self.encoding.encode_point(P)

    def decode_point(self, data: bytes) -> Tuple:
        """Decode point from bytes to (x, y)."""
        return self.encoding.decode_point(data)

    # Convert between coordinate systems

    def affine_to_extended(self, P: Tuple):
        """Convert (x, y) → (X, Y, Z, T)."""
        x, y = P
        return (x, y, 1, self.field.mul(x, y))

    def extended_to_affine(self, P: Tuple):
        """Convert (X, Y, Z, T) → (x, y)."""
        X, Y, Z, _ = P
        z_inv = self.field.inv(Z)
        return (self.field.mul(X, z_inv), self.field.mul(Y, z_inv))

    # Point addition
    @abstractmethod
    def add(self, P: Tuple, Q: Tuple) -> Tuple:
        """Add points P and Q."""
        raise NotImplementedError

    # Point doubling
    @abstractmethod
    def doubling(self, P: Tuple) -> Tuple:
        """Double point P."""
        raise NotImplementedError

    # Scalar multiplication
    def scalar_mult(self, k: int, P=None) -> Tuple:
        """Multiply point P by scalar k using double-and-add algorithm. If P is None, use the base point."""
        if P is None:
            P = self.affine_to_extended(self.base_point)
        
        Q = (0, 1, 1, 0)  # Neutral element in extended coordinates
        for bit in reversed(bin(k)[2:]):
            if bit == '1':
                Q = self.add(Q, P)
            P = self.doubling(P)
        
        return Q
