from typing import Tuple
from eddsa.curves.base.edwards_curve import EdwardsCurve
from .encoding import Ed448Encoding
from .field_ops import Ed448FieldOps
from .constants import d, BASE


class Ed448Curve(EdwardsCurve):
    def __init__(self):
        self._field = Ed448FieldOps()
        self._encoding = Ed448Encoding(self._field)
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
        X1, Y1, Z1, _ = P
        X2, Y2, Z2, _ = Q

        A = Z1 * Z2
        B = A**2
        C = X1 * X2
        D = Y1 * Y2
        E = d * C * D
        F = B - E
        G = B + E
        H = (Y1 + X1) * (Y2 + X2)

        X3 = self._field.mul(A, F*(H - C - D))
        Y3 = self._field.mul(A, G*(D - C))
        Z3 = self._field.mul(F, G)

        return (X3, Y3, Z3, _)

    # Point doubling
    def double(self, P: Tuple) -> Tuple:
        X1, Y1, Z1, _ = P

        B = (X1+Y1) ** 2
        C = X1**2
        D = Y1**2
        E = C + D
        H = Z1**2
        J = E - 2 * H

        X3 = self._field.mul((B - E), J)
        Y3 = self._field.mul(E, (C - D))
        Z3 = self._field.mul(E, J)

        return (X3, Y3, Z3, _)
