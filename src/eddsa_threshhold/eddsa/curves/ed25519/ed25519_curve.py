from typing import Tuple
from eddsa_threshhold.eddsa.curves.base.edwards_curve import EdwardsCurve
from .encoding import Ed25519Encoding
from .field_ops import Ed25519FieldOps
from .constants import d, BASE


class Ed25519Curve(EdwardsCurve):
    """
    Ed25519 curve implementation.

    See base class EdwardsCurve for method descriptions.
    """

    def __init__(self):
        self._field = Ed25519FieldOps()
        self._encoding = Ed25519Encoding(self._field)
        self.d = d

    @property
    def field(self):
        return self._field

    @property
    def encoding(self):
        return self._encoding

    @property
    def base_point(self):
        return BASE

    # Point addition
    def add(self, P: Tuple, Q: Tuple) -> Tuple:
        X1, Y1, Z1, T1 = P
        X2, Y2, Z2, T2 = Q

        A = (Y1 - X1) * (Y2 - X2)
        B = (Y1 + X1) * (Y2 + X2)
        C = T1 * 2 * self.d * T2
        D = Z1 * 2 * Z2
        E = B - A
        F = D - C
        G = D + C
        H = B + A

        X3 = self._field.mul(E, F)
        Y3 = self._field.mul(G, H)
        T3 = self._field.mul(E, H)
        Z3 = self._field.mul(F, G)

        return (X3, Y3, Z3, T3)

    # Point doubling
    def double(self, P: Tuple) -> Tuple:
        X1, Y1, Z1, T1 = P

        A = X1**2
        B = Y1**2
        C = 2 * Z1**2
        H = A + B
        E = H - (X1 + Y1)**2
        G = A - B
        F = C + G

        X3 = self._field.mul(E, F)
        Y3 = self._field.mul(G, H)
        T3 = self._field.mul(E, H)
        Z3 = self._field.mul(F, G)

        return (X3, Y3, Z3, T3)
