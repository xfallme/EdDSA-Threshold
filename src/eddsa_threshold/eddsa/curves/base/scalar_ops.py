from abc import ABC, abstractmethod
from secrets import randbelow


class ScalarOps(ABC):
    """
    Abstract class representing scalar-related math modulo the group order.
    
    All operations return integers representing scalars.
    """

    @property
    @abstractmethod
    def order(self) -> int:
        raise NotImplementedError
    
    @property
    @abstractmethod
    def identity(self) -> int:
        """Return the identity scalar."""
        raise NotImplementedError

    def inv(self, x: int) -> int:
        """Multiplicative inverse in the field GF(order)."""
        # https://en.wikipedia.org/wiki/Finite_field_arithmetic
        return pow(x, self.order - 2, self.order)

    def reduce(self, k: int) -> int:
        """Reduce any integer modulo the group order."""
        return k % self.order

    def random_scalar(self) -> int:
        """Fine for this project; NOT PRODUCTION SECURE."""
        return randbelow(self.order)
