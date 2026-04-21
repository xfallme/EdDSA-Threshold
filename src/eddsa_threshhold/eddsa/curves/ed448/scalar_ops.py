from eddsa_threshhold.eddsa.curves.base.scalar_ops import ScalarOps
from .constants import L


class Ed448ScalarOps(ScalarOps):
    @property
    def order(self) -> int:
        return L
