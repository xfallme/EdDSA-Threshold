from eddsa_threshhold.eddsa.curves.base.field_ops import FieldOps
from .constants import p


class Ed25519FieldOps(FieldOps):
    """
    Finite field operations modulo the prime p = 2^255 - 19 for Ed25519.
    """

    @property
    def p(self) -> int:
        return p
