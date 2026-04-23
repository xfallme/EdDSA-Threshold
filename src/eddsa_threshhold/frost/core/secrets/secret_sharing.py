from abc import ABC, abstractmethod

from eddsa_threshhold.eddsa.curves.base.scalar_ops import ScalarOps
from eddsa_threshhold.frost.core.types.secrets import SecretShare


class SecretSharing(ABC):
    def __init__(self, threshold: int, num_shares: int, scalar_ops: ScalarOps):
        self.t = threshold
        self.n = num_shares
        self.scalar_ops = scalar_ops

    @abstractmethod
    def split(self, secret: int) -> list[SecretShare]:
        """
        Split the secret into n shares with a threshold of t.
        """
        raise NotImplementedError

    def reconstruct(self, shares: list[SecretShare]) -> int:
        """
        Reconstruct the secret from at least t shares.
        """
        raise NotImplementedError
