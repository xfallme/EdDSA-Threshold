from abc import ABC, abstractmethod
from secrets import randbelow


class ScalarOps(ABC):
    """
    Abstract class representing scalar-related math:
    - reduction mod order
    - random scalar generation
    """

    @property
    @abstractmethod
    def order(self) -> int:
        raise NotImplementedError

    def reduce(self, k: int) -> int:
        """Reduce any integer modulo the group order."""
        return k % self.order

    def random_scalar(self) -> int:
        """Fine for this project; NOT PRODUCTION SECURE."""
        return randbelow(self.order)
