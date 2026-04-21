from typing import Tuple

from eddsa_threshhold.eddsa.curves.base.edwards_curve import EdwardsCurve


def case_ed25519() -> Tuple[EdwardsCurve, object]:
    """Inputs for ed25519 curve tests"""
    import eddsa_threshhold.eddsa.curves.ed25519.ed25519_curve as ed25519
    import eddsa_threshhold.eddsa.curves.ed25519.constants as ed25519_constants

    return ed25519.Ed25519Curve(), ed25519_constants


def case_ed448() -> Tuple[EdwardsCurve, object]:
    """Inputs for ed448 curve tests"""
    import eddsa_threshhold.eddsa.curves.ed448.ed448_curve as ed448
    import eddsa_threshhold.eddsa.curves.ed448.constants as ed448_constants

    return ed448.Ed448Curve(), ed448_constants
