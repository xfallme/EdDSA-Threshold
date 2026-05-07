from eddsa_threshold.eddsa.curves.base.field_ops import FieldOps
from .constants import p


class Ed448FieldOps(FieldOps):
    """
    Finite field operations modulo the prime p = 2^448 - 2^224 - 1 for Ed448.
    """

    @property
    def p(self) -> int:
        return p
