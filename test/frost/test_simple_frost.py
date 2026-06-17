from types import SimpleNamespace
from typing import Callable

from pytest_cases import parametrize_with_cases

from eddsa_threshold.eddsa.curves.base.edwards_curve import EdwardsCurve
from eddsa_threshold.frost.core.base.frost_hashing import FrostHashing
from eddsa_threshold.frost.trusted_dealer import FrostTrustedDealer
from eddsa_threshold.frost.core.frost_types import SigningPackage
from eddsa_threshold.frost.core.util import binding_factor_for_participant, compute_binding_factors
from eddsa_threshold.frost.participant import FrostParticipant
from eddsa_threshold.frost.coordinator import FrostCoordinator


@parametrize_with_cases("vector, hashing_con, curve_con, verifier", cases="test_cases_simple_frost")
def test_simple_frost(mocker, vector: SimpleNamespace, hashing_con: Callable[[], FrostHashing], curve_con: Callable[[], EdwardsCurve], verifier: Callable):
    """
    End-to-end test for a simple 2-of-3 FROST signing flow, using test vectors from the FROST paper. 
    This test covers the happy path and checks intermediate values against the test vectors at each step.
    Uses mocking to control randomness for deterministic outputs that can be checked against the test vectors.
    """

    m = bytes.fromhex(vector.message)

    curve = curve_con()
    
    # normally the trusted dealer would not return these values, but we intercept them here for testing purposes to check against the test vectors
    pytest_container: dict = {
        "shares": [],
        "group_info": None,
        "vss_commitment": []
    }
    test_connections = {1: lambda share, group_info, vss_commitment: _intercept_trusted_dealer_keygen(pytest_container, share, group_info, vss_commitment), 2: lambda share, group_info, vss_commitment: _intercept_trusted_dealer_keygen(pytest_container, share, group_info, vss_commitment), 3: lambda share, group_info, vss_commitment: _intercept_trusted_dealer_keygen(pytest_container, share, group_info, vss_commitment)}
    
    trusted_dealer = FrostTrustedDealer.from_private_bytes(vector.group_secret_key, vector.MIN_PARTICIPANTS, vector.participant_list, test_connections, hashing_con(), curve_con())
    mocker.patch('eddsa_threshold.eddsa.curves.base.scalar_ops.ScalarOps.random_scalar', return_value=vector.share_polynomial_coefficients[1])
    trusted_dealer.keygen()

    # This block checks secret sharing outputs against test vectors
    assert pytest_container["group_info"].group_public_key == bytes.fromhex(vector.group_public_key_expected)
    assert pytest_container["shares"][0].index == 1
    assert pytest_container["shares"][0].value == vector.participant_shares[1]
    assert pytest_container["shares"][1].index == 2
    assert pytest_container["shares"][1].value == vector.participant_shares[2]
    assert pytest_container["shares"][2].index == 3
    assert pytest_container["shares"][2].value == vector.participant_shares[3]

    coordinator = FrostCoordinator(vector.MIN_PARTICIPANTS, vector.participant_list, pytest_container["group_info"], hashing_con(), curve_con())
    
    session_id = coordinator.create_signing_session(m)
    
    # This test acts as distributor for the participants, in a real implementation this would be done out-of-band
    p1 = FrostParticipant(1, pytest_container["shares"][0], pytest_container["group_info"], hashing_con(), curve_con())
    p2 = FrostParticipant(2, pytest_container["shares"][1], pytest_container["group_info"], hashing_con(), curve_con())
    p3 = FrostParticipant(3, pytest_container["shares"][2], pytest_container["group_info"], hashing_con(), curve_con())
    
    coordinator.register_participant_to_session(session_id, 1)
    coordinator.register_participant_to_session(session_id, 3)
    coordinator.start_signing_session(session_id)

    mocker.patch('eddsa_threshold.frost.core.util.os.urandom', side_effect=[bytes.fromhex(vector.hiding_nonce_randomness[1]), bytes.fromhex(vector.binding_nonce_randomness[1]), bytes.fromhex(vector.hiding_nonce_randomness[3]), bytes.fromhex(vector.binding_nonce_randomness[3])])
    c1 = p1.round_one_commit(session_id)
    # c2 = p2.round_one_commit()
    c3 = p3.round_one_commit(session_id)

    commitments = [c1, c3]
    binding_factors = compute_binding_factors(pytest_container["group_info"].group_public_key, commitments, m, hashing_con(), curve_con().encoding)

    # This block checks round one outputs against test vectors
    assert c1.participant_id == 1
    assert p1._nonce_pair[session_id] == (vector.hiding_nonce[1], vector.binding_nonce[1])
    assert curve.encode_affine_point(c1.hiding_nonce_commitment) == bytes.fromhex(vector.hiding_nonce_commitment[1])
    assert curve.encode_affine_point(c1.binding_nonce_commitment) == bytes.fromhex(vector.binding_nonce_commitment[1])
    assert c3.participant_id == 3
    assert p3._nonce_pair[session_id] == (vector.hiding_nonce[3], vector.binding_nonce[3])
    assert curve.encode_affine_point(c3.hiding_nonce_commitment) == bytes.fromhex(vector.hiding_nonce_commitment[3])
    assert curve.encode_affine_point(c3.binding_nonce_commitment) == bytes.fromhex(vector.binding_nonce_commitment[3])
    assert binding_factor_for_participant(1, binding_factors) == vector.binding_factor[1]
    assert binding_factor_for_participant(3, binding_factors) == vector.binding_factor[3]
    
    coordinator.receive_commitment(session_id, 1, c1)
    coordinator.receive_commitment(session_id, 3, c3)

    signing_package = coordinator.create_signing_package(session_id)

    s1 = p1.round_two_sign(signing_package)
    s3 = p3.round_two_sign(signing_package)
    coordinator.receive_signature_share(session_id, 1, s1)
    coordinator.receive_signature_share(session_id, 3, s3)
    sig = coordinator.aggregate(session_id)

    # This block checks round two outputs against test vectors
    assert s1 == vector.sig_share[1]
    assert s3 == vector.sig_share[3]
    assert sig == bytes.fromhex(vector.sig_expected)

    is_valid = verifier(sig, m, pytest_container["group_info"].group_public_key)
    assert is_valid, "Signature verification failed"
    
    print("\n" + vector.alg)
    print("Running test with 2 out of 3")
    print("Message:", m.hex())
    print("Group Public Key:", pytest_container["group_info"].group_public_key.hex())
    print("Signature:", sig.hex())

def _intercept_trusted_dealer_keygen(pytest_container, share, group_info, vss_commitment):
    if pytest_container["group_info"] is None:
        pytest_container["group_info"] = group_info
    else:
        if pytest_container["group_info"] != group_info:
            raise ValueError("Group info mismatch between participants")

    if len(pytest_container["vss_commitment"]) == 0:
        pytest_container["vss_commitment"] = vss_commitment
    else:
        if pytest_container["vss_commitment"] != vss_commitment:
            raise ValueError("VSS commitment mismatch between participants")
    
    pytest_container["shares"].append(share)