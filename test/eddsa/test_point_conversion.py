from pytest_cases import parametrize_with_cases

from eddsa_threshhold.eddsa.curves.base.edwards_curve import EdwardsCurve


@parametrize_with_cases("curve, constants", cases="test_cases_curves")
def test_to_affine(curve: EdwardsCurve, constants):
    """Test conversion from extended to affine coordinates."""
    P_ext = curve.affine_to_extended(constants.BASE)
    P_aff = curve.extended_to_affine(P_ext)

    Z_ext = curve.affine_to_extended(constants.IDENTITY)
    Z_aff = curve.extended_to_affine(Z_ext)

    assert P_aff == curve.base_point, "Base point conversion to affine failed"
    assert Z_aff == constants.IDENTITY, "Identity point conversion to affine failed"


@parametrize_with_cases("curve, constants", cases="test_cases_curves")
def test_to_extended(curve: EdwardsCurve, constants):
    """Test conversion from affine to extended coordinates."""
    Z_aff = constants.IDENTITY
    Z_ext = curve.affine_to_extended(Z_aff)

    assert Z_ext == (0, 1, 1, 0)
