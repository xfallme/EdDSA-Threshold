from typing import Tuple
import os

from eddsa_threshhold.eddsa.curves.base.edwards_curve import EdwardsCurve
from eddsa_threshhold.eddsa.curves.base.encoding import Encoding
from eddsa_threshhold.frost.core.base.frost_hashing import FrostHashing
from eddsa_threshhold.frost.core.types import BindingFactor, NonceCommitment, ParticipantId


def generate_nonce(secret: bytes, hashing: FrostHashing) -> int:
    random = os.urandom(32)
    return hashing.h3(random + secret)


def encode_group_commitments(commitments: list[NonceCommitment], encoding: Encoding) -> bytes:
    """
    Encodes a list of NonceCommitments into bytes.
    """
    # Sort by participant id for deterministic encoding
    group_commitments = sorted(commitments, key=lambda c: c.participant_id)

    encoded_group_commitment = b""

    for commitment in group_commitments:
        encoded_commitment = encoding.encode_scalar(commitment.participant_id) + encoding.encode_point(
            commitment.hiding_commitment) + encoding.encode_point(commitment.binding_commitment)
        encoded_group_commitment = encoded_group_commitment + encoded_commitment

    return encoded_group_commitment


def participants_from_commitment_list(commitments: list[NonceCommitment]) -> list[ParticipantId]:
    """
    Extracts the set of participant ids from a list of NonceCommitments.
    """
    return list(commitment.participant_id for commitment in commitments)


def binding_factor_for_participant(participant_id: ParticipantId, binding_factors: list[BindingFactor]) -> int:
    """
    Retrieves the binding factor for a given participant id from a list of BindingFactors.
    """
    for factor in binding_factors:
        if factor.participant_id == participant_id:
            return factor.binding_factor

    raise ValueError(f"binding factor not found for participant {participant_id}")


def compute_binding_factors(group_public_key: bytes, commitments: list[NonceCommitment], message: bytes, hashing: FrostHashing, encoding: Encoding) -> list[BindingFactor]:

    message_hash = hashing.h4(message)
    encoded_commitments_hash = hashing.h5(encode_group_commitments(commitments, encoding))

    rho_prefix = group_public_key + message_hash + encoded_commitments_hash

    binding_factors = []
    for commitment in commitments:
        rho_input = rho_prefix + encoding.encode_scalar(commitment.participant_id)
        binding_factor = hashing.h1(rho_input)
        binding_factors.append((commitment.participant_id, binding_factor))
    return binding_factors


# EdwardsCurve for now, because this project only implements FROST for EdDSA, but this can be made more generic if needed.
def compute_group_commitment(commitments: list[NonceCommitment], binding_factors: list[BindingFactor], curve: EdwardsCurve) -> Tuple:
    """
    Computes the group commitment from a list of NonceCommitments and BindingFactors.
    """
    group_commitment = curve.base_point

    for commitment in commitments:
        binding_factor = binding_factor_for_participant(commitment.participant_id, binding_factors)
        binding_nonce = curve.scalar_mult(commitment.binding_commitment, binding_factor)

        group_commitment = curve.add(group_commitment, commitment.hiding_commitment)
        group_commitment = curve.add(group_commitment, binding_nonce)

    return group_commitment


def compute_challenge(group_commitment: Tuple, group_public_key: bytes, message: bytes, hashing: FrostHashing, encoding: Encoding) -> int:
    """
    Computes the signing challenge c = H(R || A || m) where R is the group commitment, A is the group public key, and m is the message.
    """
    challenge_input = encoding.encode_point(group_commitment) + group_public_key + message
    return hashing.h2(challenge_input)
