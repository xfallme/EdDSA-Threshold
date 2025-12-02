from pytest_cases import parametrize_with_cases


@parametrize_with_cases("curve, BASE, IDENTITY", cases="test_cases_curves")
def test_to_affine(curve, BASE, IDENTITY):
    """Test conversion from extended to affine coordinates."""
    P_ext = curve.affine_to_extended(BASE)
    P_aff = curve.extended_to_affine(P_ext)

    Z_ext = curve.affine_to_extended(IDENTITY)
    Z_aff = curve.extended_to_affine(Z_ext)

    assert P_aff == curve.base_point
    assert Z_aff == IDENTITY


@parametrize_with_cases("curve, _, IDENTITY", cases="test_cases_curves")
def test_to_extended(curve, _, IDENTITY):
    """Test conversion from affine to extended coordinates."""
    Z_aff = IDENTITY
    Z_ext = curve.affine_to_extended(Z_aff)

    assert Z_ext == (0, 1, 1, 0)
