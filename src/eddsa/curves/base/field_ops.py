from abc import ABC, abstractmethod


class FieldOps(ABC):
    """
    Abstract base class for finite field operations modulo a prime p.

    All operations return integers representing field elements.
    """

    @property
    @abstractmethod
    def p(self) -> int:
        """Prime modulus for the field GF(p)."""
        raise NotImplementedError

    def add(self, x: int, y: int) -> int:
        return (x + y) % self.p

    def sub(self, x: int, y: int) -> int:
        return (x - y) % self.p

    def mul(self, x: int, y: int) -> int:
        return (x * y) % self.p

    def neg(self, x: int) -> int:
        return -x % self.p

    def inv(self, x: int) -> int:
        # https://en.wikipedia.org/wiki/Finite_field_arithmetic
        return pow(x, self.p - 2, self.p)

    def sqr(self, x: int) -> int:
        return (x * x) % self.p

    def pow(self, x: int, e: int) -> int:
        return pow(x, e, self.p)

    def reduce(self, x: int) -> int:
        return x % self.p
