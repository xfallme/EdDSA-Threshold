from eddsa_threshold.eddsa.curves.base.scalar_ops import ScalarOps
from .constants import L, SCALAR_SIZE


class Ed448ScalarOps(ScalarOps):
    @property
    def order(self) -> int:
        return L

    @property
    def identity(self) -> int:
        return 0