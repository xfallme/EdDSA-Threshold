from dataclasses import dataclass


@dataclass(frozen=True)
class SecretShare:
    index: int   # x-coordinate
    value: int   # y = f(x) mod n