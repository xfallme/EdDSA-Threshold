from pytest_cases import parametrize_with_cases

from eddsa_threshold.eddsa.curves.base.field_ops import FieldOps


@parametrize_with_cases("field", cases="test_cases_fields")
def test_add(field: FieldOps):
    """Test field addition"""
    x = 123456789012345678901234567890
    y = 987654321098765432109876543210
    result = field.add(x, y)
    expected = (x + y) % field.p
    assert result == expected


@parametrize_with_cases("field", cases="test_cases_fields")
def test_sub(field: FieldOps):
    """Test field subtraction"""
    x = 987654321098765432109876543210
    y = 1123456789012345678901234567890
    result = field.sub(x, y)
    expected = (x - y) % field.p
    assert result == expected


@parametrize_with_cases("field", cases="test_cases_fields")
def test_mul(field: FieldOps):
    """Test field multiplication"""
    x = 12345678901234567890
    y = 98765432109876543210
    result = field.mul(x, y)
    expected = (x * y) % field.p
    assert result == expected


@parametrize_with_cases("field", cases="test_cases_fields")
def test_neg(field: FieldOps):
    """Test field negation"""
    x = 123456789012345678901234567890
    result = field.neg(x)
    expected = (-x) % field.p
    assert result == expected


@parametrize_with_cases("field", cases="test_cases_fields")
def test_inv(field: FieldOps):
    """Test field inversion"""
    x = 123456789012345678901234567890
    inv_x = field.inv(x)
    result = field.mul(x, inv_x)
    assert result == 1 % field.p


@parametrize_with_cases("field", cases="test_cases_fields")
def test_sqr(field: FieldOps):
    """Test field squaring"""
    x = 123456789012345678901234567890
    result = field.sqr(x)
    expected = (x * x) % field.p
    assert result == expected


@parametrize_with_cases("field", cases="test_cases_fields")
def test_pow(field: FieldOps):
    """Test field exponentiation"""
    x = 123456789012345678901234567890
    e = 1234567890
    result = field.pow(x, e)
    expected = pow(x, e, field.p)
    assert result == expected


@parametrize_with_cases("field", cases="test_cases_fields")
def test_reduce(field: FieldOps):
    """Test field reduction"""
    x = field.p + 12345678901234567890
    result = field.reduce(x)
    expected = x % field.p
    assert result == expected
