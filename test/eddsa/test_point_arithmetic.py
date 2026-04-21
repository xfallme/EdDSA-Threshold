from pytest_cases import parametrize_with_cases

from eddsa_threshhold.eddsa.curves.base.edwards_curve import EdwardsCurve


@parametrize_with_cases("curve, constants", cases="test_cases_curves")
def test_add_identity_left(curve: EdwardsCurve, constants):
    """P + 0 = P"""
    P = curve.affine_to_extended(constants.BASE)
    Z = curve.affine_to_extended(constants.IDENTITY)

    sum = curve.add(Z, P)

    assert curve.extended_to_affine(sum) == constants.BASE


@parametrize_with_cases("curve, constants", cases="test_cases_curves")
def test_add_identity_right(curve: EdwardsCurve, constants):
    """0 + P = P"""
    P = curve.affine_to_extended(constants.BASE)
    Z = curve.affine_to_extended(constants.IDENTITY)

    sum = curve.add(P, Z)

    assert curve.extended_to_affine(sum) == constants.BASE


@parametrize_with_cases("curve, constants", cases="test_cases_curves")
def test_commutativity(curve: EdwardsCurve, constants):
    """P + Q = Q + P"""
    P = curve.affine_to_extended(constants.BASE)
    # Pick another point by multiplying the constants.BASE point
    Q = curve.scalar_mult(32, P)

    sum1 = curve.add(P, Q)
    sum2 = curve.add(Q, P)

    assert sum1 == sum2, "Addition results differ"
    assert curve.extended_to_affine(sum1) == curve.extended_to_affine(sum2), "Affine coordinates differ"


@parametrize_with_cases("curve, constants", cases="test_cases_curves")
def test_associativity(curve: EdwardsCurve, constants):
    """(P + Q) + R = P + (Q + R)"""
    P = curve.affine_to_extended(constants.BASE)
    # Pick other points by multiplying the constants.BASE point
    Q = curve.scalar_mult(7, P)
    R = curve.scalar_mult(11, Q)

    left = curve.add(curve.add(P, Q), R)
    right = curve.add(P, curve.add(Q, R))

    assert curve.extended_to_affine(left) == curve.extended_to_affine(right)


@parametrize_with_cases("curve, constants", cases="test_cases_curves")
def test_doubling(curve: EdwardsCurve, constants):
    """P + P = 2*P"""
    P = curve.affine_to_extended(constants.BASE)
    doubled = curve.double(P)
    scalar_doubled = curve.scalar_mult(2, P)

    assert curve.extended_to_affine(doubled) == curve.extended_to_affine(scalar_doubled)


@parametrize_with_cases("curve, constants", cases="test_cases_curves")
def test_add_negative_point(curve: EdwardsCurve, constants):
    """P + (-P) = 0"""
    P = curve.affine_to_extended(constants.BASE)
    negP = curve.negate(P)

    assert curve.extended_to_affine(curve.add(P, negP)) == constants.IDENTITY


@parametrize_with_cases("curve, constants", cases="test_cases_curves")
def test_random_additions(curve: EdwardsCurve, constants):
    """General consistency test with several random scalars."""
    P = curve.affine_to_extended(constants.BASE)
    for a in [1, 2, 3, 5, 13, 57, 1003]:
        for b in [1, 4, 9, 31, 52, 900]:
            A = curve.scalar_mult(a, P)
            B = curve.scalar_mult(b, P)

            # check (a + b)P = aP + bP
            left = curve.scalar_mult(a + b, P)
            right = curve.add(A, B)

            assert curve.extended_to_affine(left) == curve.extended_to_affine(right)

            P = curve.scalar_mult(a, P)
