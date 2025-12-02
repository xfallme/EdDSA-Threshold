def case_ed25519():
    """Inputs for ed25519 curve tests"""
    import eddsa.curves.ed25519.ed25519_curve as ed25519
    import eddsa.curves.ed25519.constants as ed25519_constants

    return ed25519.Ed25519Curve(), ed25519_constants.BASE, ed25519_constants.IDENTITY


def case_ed448():
    """Inputs for ed448 curve tests"""
    import eddsa.curves.ed448.ed448_curve as ed448
    import eddsa.curves.ed448.constants as ed448_constants

    return ed448.Ed448Curve(), ed448_constants.BASE, ed448_constants.IDENTITY
