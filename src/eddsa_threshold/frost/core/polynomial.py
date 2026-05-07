from eddsa_threshold.eddsa.curves.base.scalar_ops import ScalarOps


def evaluate_polynomial(coeffs: list[int], x: int, scalar_ops: ScalarOps) -> int:
    """
    Evaluates a polynomial at a given x using Horner's method.
    """
    # https://en.wikipedia.org/wiki/Horner's_method
    result = 0
    for coeff in reversed(coeffs):
        result = result * x + coeff

    return scalar_ops.reduce(result)


def derive_interpolating_value(L: list[int], x_i: int, x: int, scalar_ops: ScalarOps) -> int:
    """
    Compute Lagrange basis coefficient λ_i(x) for arbitrary interpolation point x.
    """

    if x_i not in L:
        raise ValueError("x_i not in set")

    if len(set(L)) != len(L):
        raise ValueError("duplicate x values")

    numerator = 1
    denominator = 1

    # Compute the Lagrange basis polynomial
    # https://en.wikipedia.org/wiki/Lagrange_polynomial
    for x_j in L:
        if x_j == x_i:
            continue
        numerator = scalar_ops.mul(numerator, scalar_ops.sub(x, x_j))
        denominator = scalar_ops.mul(denominator, scalar_ops.sub(x_i, x_j))

    return scalar_ops.mul(numerator, scalar_ops.inv(denominator))
