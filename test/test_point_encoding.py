from nacl.bindings import crypto_scalarmult_ed25519_base_noclamp
from nacl.bindings import crypto_core_ed25519_from_uniform

from pytest_cases import parametrize_with_cases


@parametrize_with_cases("curve, constants", cases="test_cases_curves")
def test_identity_encoding(curve, constants):
    identity_encoding = curve.encode_affine_point(constants.IDENTITY)

    assert identity_encoding == (1).to_bytes(constants.PUBLIC_KEY_SIZE, "little")
    
@parametrize_with_cases("curve, constants", cases="test_cases_curves")
def test_base_encoding(curve, constants):
    base_encoding = curve.encode_affine_point(constants.BASE)
    base_encoding_nacl = crypto_scalarmult_ed25519_base_noclamp((1).to_bytes(32, "little"))

    assert base_encoding == base_encoding_nacl