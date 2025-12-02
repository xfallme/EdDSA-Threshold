import random
from nacl.bindings import crypto_scalarmult_ed25519_base_noclamp

from pytest_cases import parametrize_with_cases

from eddsa.curves.base.edwards_curve import EdwardsCurve
from eddsa.curves.ed25519.ed25519_curve import Ed25519Curve
from eddsa.curves.ed25519 import constants as ed25519constants
from eddsa.curves.ed448.ed448_curve import Ed448Curve
from eddsa.curves.ed448 import constants as ed448constants


@parametrize_with_cases("curve, constants", cases="test_cases_curves")
def test_identity_encoding(curve: EdwardsCurve, constants):
    identity_encoding = curve.encode_affine_point(constants.IDENTITY)

    assert identity_encoding == (1).to_bytes(
        constants.PUBLIC_KEY_SIZE, "little")


def test_base_encoding_ed25519(curve=Ed25519Curve(), constants=ed25519constants):
    # No direct libsodium access for Ed448 base point encoding test
    base_encoding = curve.encode_affine_point(constants.BASE)  # type: ignore
    base_encoding_nacl = crypto_scalarmult_ed25519_base_noclamp(
        (1).to_bytes(constants.PUBLIC_KEY_SIZE, "little"))

    assert base_encoding == base_encoding_nacl


@parametrize_with_cases("curve, constants", cases="test_cases_curves")
def test_base_encoding_decoding(curve: EdwardsCurve, constants):
    base_encoding = curve.encode_affine_point(constants.BASE)  # type: ignore
    base_decoding = curve.decode_point(base_encoding)

    assert constants.BASE == base_decoding


@parametrize_with_cases("curve, constants", cases="test_cases_curves")
def test_identity_encoding_decoding(curve: EdwardsCurve, constants):
    identity_encoding = curve.encode_affine_point(
        constants.IDENTITY)  # type: ignore
    identity_decoding = curve.decode_point(identity_encoding)

    assert constants.IDENTITY == identity_decoding


@parametrize_with_cases("curve, constants", cases="test_cases_curves")
def test_random_point_encoding_decoding(curve: EdwardsCurve, constants):
    P = curve.affine_to_extended(constants.BASE)
    for i in range(100):
        a = random.randint(1, 100000000)
        P = curve.scalar_mult(a, P)
        P_encoding = curve.encode_extended_point(P)
        P_decoding = curve.decode_point(P_encoding)

        assert curve.extended_to_affine(P) == P_decoding


def test_random_point_encoding_ed25519(curve=Ed25519Curve(), constants=ed25519constants):
    for i in range(100):
        a = random.randint(1, 100000000)
        P = curve.scalar_mult(a, curve.affine_to_extended(constants.BASE))
        P_encoding = curve.encode_extended_point(P)

        P_encoding_nacl = crypto_scalarmult_ed25519_base_noclamp(
            a.to_bytes(constants.PUBLIC_KEY_SIZE, "little"))

        assert P_encoding == P_encoding_nacl
