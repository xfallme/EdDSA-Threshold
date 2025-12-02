from pytest_cases import parametrize_with_cases


@parametrize_with_cases("curve, BASE, IDENTITY", cases="test_cases_curves")
def test_add_identity_left(curve, BASE, IDENTITY):
    """P + 0 = P"""
    P = curve.affine_to_extended(BASE)
    Z = curve.affine_to_extended(IDENTITY)
    
    sum = curve.add(Z, P)

    assert curve.extended_to_affine(sum) == BASE

@parametrize_with_cases("curve, BASE, IDENTITY", cases="test_cases_curves")
def test_add_identity_right(curve, BASE, IDENTITY):
    """0 + P = P"""
    P = curve.affine_to_extended(BASE)
    Z = curve.affine_to_extended(IDENTITY)
    
    sum = curve.add(P, Z)

    assert curve.extended_to_affine(sum) == BASE

@parametrize_with_cases("curve, BASE, IDENTITY", cases="test_cases_curves")
def test_commutativity(curve, BASE, IDENTITY):
    """P + Q = Q + P"""
    P = curve.affine_to_extended(BASE)
    # Pick another point by multiplying the base point
    Q = curve.scalar_mult(32, P)
    
    sum1 = curve.add(P, Q)
    sum2 = curve.add(Q, P)

    assert sum1 == sum2
    assert curve.extended_to_affine(sum1) == curve.extended_to_affine(sum2)

@parametrize_with_cases("curve, BASE, IDENTITY", cases="test_cases_curves")
def test_associativity(curve, BASE, IDENTITY):
    """(P + Q) + R = P + (Q + R)"""
    P = curve.affine_to_extended(BASE)
    # Pick other points by multiplying the base point
    Q = curve.scalar_mult(7, P)
    R = curve.scalar_mult(11, Q)

    left = curve.add(curve.add(P, Q), R)
    right = curve.add(P, curve.add(Q, R))

    assert curve.extended_to_affine(left) == curve.extended_to_affine(right)

@parametrize_with_cases("curve, BASE, IDENTITY", cases="test_cases_curves")
def test_doubling(curve, BASE, IDENTITY):
    """P + P = 2*P"""
    P = curve.affine_to_extended(BASE)
    doubled = curve.double(P)
    scalar_doubled = curve.scalar_mult(2, P)
    
    assert curve.extended_to_affine(doubled) == curve.extended_to_affine(scalar_doubled)

@parametrize_with_cases("curve, BASE, IDENTITY", cases="test_cases_curves")
def test_add_negative_point(curve, BASE, IDENTITY):
    """P + (-P) = 0"""
    P = curve.affine_to_extended(BASE)
    negP = curve.negate(P)

    assert curve.extended_to_affine(curve.add(P, negP)) == IDENTITY

@parametrize_with_cases("curve, BASE, IDENTITY", cases="test_cases_curves")
def test_random_additions(curve, BASE, IDENTITY):
    """General consistency test with several random scalars."""
    P = curve.affine_to_extended(BASE)
    for a in [1, 2, 3, 5, 13, 57, 1003]:
        for b in [1, 4, 9, 31, 52, 900]:
            A = curve.scalar_mult(a, P)
            B = curve.scalar_mult(b, P)

            # check (a + b)P = aP + bP
            left = curve.scalar_mult(a + b, P)
            right = curve.add(A, B)

            assert curve.extended_to_affine(left) == curve.extended_to_affine(right)
            
            P = curve.scalar_mult(a, P)
