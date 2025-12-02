from typing import Tuple

from eddsa.curves.base.encoding import Encoding
from eddsa.curves.ed25519.field_ops import Ed25519FieldOps
from .constants import SCALAR_SIZE, PUBLIC_KEY_SIZE, d, a


class Ed25519Encoding(Encoding):
    """
    Byte encoding/decoding layer for Ed25519.
    """

    def __init__(self, field_ops: Ed25519FieldOps):
        self._field = field_ops

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
        
        y_bytes = bytearray(y_bytes)
        if x & 1:
            y_bytes[-1] |= 0x80
        
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
        
        y2 = self._field.pow(y, 2)
        u = (y2 - 1) % self._field.p
        v = (d * y2 - a) % self._field.p
        
        v3 = self._field.pow(v, 3)
        v7 = self._field.pow(v, 7)
        
        w = (u * v3 * self._field.pow((u * v7), ((self._field.p - 5) // 8))) % self._field.p
        
        if (v * w**2) % self._field.p == u:
            x = w
        elif (v * w**2) % self._field.p == -u:
            x = (w * 2**((self._field.p - 1) // 4))
        else:
            raise ValueError("Invalid point encoding - SQRT failure")
        
        if x == 0 and x_lsb == 1:
            raise ValueError("Invalid point encoding - x is zero but lsb is 1")
        
        if (x % 2) == x_lsb:
            return (x, y)
        else:
            return (self._field.p - x, y)
            
