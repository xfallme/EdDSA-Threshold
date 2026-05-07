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

    def add(self, x: int, y: int) -> int:
        """Addition in the field GF(order)."""
        return (x + y) % self.order

    def sub(self, x: int, y: int) -> int:
        """Subtraction in the field GF(order)."""
        return (x - y) % self.order

    def mul(self, x: int, y: int) -> int:
        """Multiplication in the field GF(order)."""
        return (x * y) % self.order

    def neg(self, x: int) -> int:
        """Negation in the field GF(order)."""
        return -x % self.order

    def inv(self, x: int) -> int:
        """Multiplicative inverse in the field GF(order)."""
        # https://en.wikipedia.org/wiki/Finite_field_arithmetic
        return pow(x, self.order - 2, self.order)

    def sqr(self, x: int) -> int:
        """Squaring in the field GF(order)."""
        return (x * x) % self.order

    def pow(self, x: int, e: int) -> int:
        """Exponentiation in the field GF(order)."""
        return pow(x, e, self.order)

    def reduce(self, k: int) -> int:
        """Reduce any integer modulo the group order."""
        return k % self.order

    def random_scalar(self) -> int:
        """Fine for this project; NOT PRODUCTION SECURE."""
        return randbelow(self.order)
