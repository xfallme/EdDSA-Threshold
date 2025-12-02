from pytest_cases import parametrize_with_cases


@parametrize_with_cases("field", cases="test_cases_fields")
def test_add(field):
    """Test field addition"""
    x = 123456789012345678901234567890
    y = 987654321098765432109876543210
    result = field.add(x, y)
    expected = (x + y) % field.p
    assert result == expected


@parametrize_with_cases("field", cases="test_cases_fields")
def test_sub(field):
    """Test field subtraction"""
    x = 987654321098765432109876543210
    y = 1123456789012345678901234567890
    result = field.sub(x, y)
    expected = (x - y) % field.p
    assert result == expected


@parametrize_with_cases("field", cases="test_cases_fields")
def test_mul(field):
    """Test field multiplication"""
    x = 12345678901234567890
    y = 98765432109876543210
    result = field.mul(x, y)
    expected = (x * y) % field.p
    assert result == expected


@parametrize_with_cases("field", cases="test_cases_fields")
def test_neg(field):
    """Test field negation"""
    x = 123456789012345678901234567890
    result = field.neg(x)
    expected = (-x) % field.p
    assert result == expected


@parametrize_with_cases("field", cases="test_cases_fields")
def test_inv(field):
    """Test field inversion"""
    x = 123456789012345678901234567890
    inv_x = field.inv(x)
    result = field.mul(x, inv_x)
    assert result == 1 % field.p


@parametrize_with_cases("field", cases="test_cases_fields")
def test_sqr(field):
    """Test field squaring"""
    x = 123456789012345678901234567890
    result = field.sqr(x)
    expected = (x * x) % field.p
    assert result == expected


@parametrize_with_cases("field", cases="test_cases_fields")
def test_pow(field):
    """Test field exponentiation"""
    x = 123456789012345678901234567890
    e = 1234567890
    result = field.pow(x, e)
    expected = pow(x, e, field.p)
    assert result == expected


@parametrize_with_cases("field", cases="test_cases_fields")
def test_reduce(field):
    """Test field reduction"""
    x = field.p + 12345678901234567890
    result = field.reduce(x)
    expected = x % field.p
    assert result == expected
