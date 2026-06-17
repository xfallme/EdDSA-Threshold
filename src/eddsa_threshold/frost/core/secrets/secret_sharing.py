from abc import ABC, abstractmethod
from typing import Tuple

from eddsa_threshold.eddsa.curves.base.scalar_ops import ScalarOps
from eddsa_threshold.frost.core.frost_types import SecretShare


class SecretSharing(ABC):
    def __init__(self, threshold: int, num_shares: int, scalar_ops: ScalarOps):
        self.t = threshold
        self.n = num_shares
        self.scalar_ops = scalar_ops

    @abstractmethod
    def split(self, secret: int) -> Tuple[list[SecretShare], list[int]]:
        """
        Split the secret into n shares with a threshold of t.
        """
        raise NotImplementedError
    
    @abstractmethod
    def reconstruct(self, shares: list[SecretShare]) -> int:
        """
        Reconstruct the secret from at least t shares.
        """
        raise NotImplementedError
