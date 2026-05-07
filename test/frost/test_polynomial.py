from pytest_cases import parametrize_with_cases

from eddsa_threshold.eddsa.curves.base.scalar_ops import ScalarOps
from eddsa_threshold.frost.core.polynomial import derive_interpolating_value, evaluate_polynomial


@parametrize_with_cases("scalar_ops", cases="test_cases_scalars")
def test_evaluate_polynomial(scalar_ops: ScalarOps):
    """Test that polynomial evaluation works correctly."""
    coeffs = [3, 2, 1] # Represents the polynomial 1*x^2 + 2*x + 3
    x = 5
    expected = scalar_ops.reduce(1 * x**2 + 2 * x + 3)
    result = evaluate_polynomial(coeffs, x, scalar_ops)
    assert result == expected
    
@parametrize_with_cases("scalar_ops", cases="test_cases_scalars")
def test_basic_interpolation_values(scalar_ops: ScalarOps):
    """Test that interpolation values are correct for a simple case."""
    L = [1, 2, 3]
    
    # The weight for x_i should be 1 at x_i and 0 at all other points in L
    for x_i in L:
        assert derive_interpolating_value(L, x_i, x_i, scalar_ops) == 1
        
        for x_k in L:
            if x_k == x_i:
                continue
            assert derive_interpolating_value(L, x_i, x_k, scalar_ops) == 0