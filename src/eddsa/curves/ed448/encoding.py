from typing import Tuple

from eddsa.curves.base.encoding import Encoding
from eddsa.curves.ed448.field_ops import Ed448FieldOps
from .constants import SCALAR_SIZE, PUBLIC_KEY_SIZE, d, a


class Ed448Encoding(Encoding):
    """
    Byte encoding/decoding layer for Ed448.
    """

    def __init__(self, FieldOps: Ed448FieldOps):
        self._field = FieldOps

    @property
    def scalar_size(self) -> int:
        """Size in bytes of a private scalar."""
        return SCALAR_SIZE

    @property
    def point_size(self) -> int:
        """Size in bytes of an encoded public key point."""
        return PUBLIC_KEY_SIZE

    def encode_point(self, P: Tuple) -> bytes:
        """Encode point P=(x, y) to bytes."""
        x, y = P
        y_bytes = y.to_bytes(self.point_size, byteorder='little')
        
        x_lsb = x & 1
        y_bytes = bytearray(y_bytes)
        y_bytes[-1] |= (x_lsb << 7)
        
        return bytes(y_bytes)

    def decode_point(self, data: bytes) -> Tuple:
        """Decode point from bytes to (x_lsb, y)."""
        if len(data) != self.point_size:
            raise ValueError("Invalid point size")
        
        y_bytes = bytearray(data)
        x_lsb = (y_bytes[-1] >> 7) & 1
        y_bytes[-1] &= 0x7F  # Clear the MSB
        
        y = int.from_bytes(y_bytes, byteorder='little')
        if y >= self._field.p:
            raise ValueError("Invalid point encoding - y out of range")
        
        u = y^2 - 1
        v = d * y^2 - a
        w = (u * v^3 * (u^5 * v^3)^((self._field.p - 3) // 4)) % self._field.p
        
        if (v * w^2) == u:
            x = w
        else:
            raise ValueError("Invalid point encoding - SQRT failure")
        
        if x == 0 & x_lsb == 1:
            raise ValueError("Invalid point encoding - x is zero but lsb is 1")
        
        if (x % 2) == x_lsb:
            return (x, y)
        else:
            return (self._field.p - x, y)
            
