from abc import ABC, abstractmethod
from typing import Final, Tuple

from eddsa_threshold.eddsa.curves.base.scalar_ops import ScalarOps
from eddsa_threshold.frost.core.frost_types import SecretShare


class SecretSharing(ABC):
    def __init__(self, threshold: int, num_shares: int, scalar_ops: ScalarOps):
        self.T: Final[int] = threshold
        self.N: Final[int] = num_shares
        self.scalar_ops: Final[ScalarOps] = scalar_ops

    @abstractmethod
    def split(self, secret: int) -> Tuple[list[SecretShare], list[int]]:
        """
        Split the secret into N shares with a threshold of T.
        """
        raise NotImplementedError
    
    @abstractmethod
    def reconstruct(self, shares: list[SecretShare]) -> int:
        """
        Reconstruct the secret from at least T shares.
        """
        raise NotImplementedError
