from eddsa_threshhold.eddsa.curves.base.scalar_ops import ScalarOps
from .constants import L, SCALAR_SIZE


class Ed25519ScalarOps(ScalarOps):
    @property
    def order(self) -> int:
        return L
    
    @property
    def scalar_size(self) -> int:
        return SCALAR_SIZE
