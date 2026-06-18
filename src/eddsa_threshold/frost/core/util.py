from typing import Tuple
import os

from eddsa_threshold.eddsa.curves.base.edwards_curve import EdwardsCurve
from eddsa_threshold.eddsa.curves.base.encoding import Encoding
from eddsa_threshold.eddsa.curves.base.scalar_ops import ScalarOps
from eddsa_threshold.frost.core.base.frost_hashing import FrostHashing
from eddsa_threshold.frost.core.frost_types import BindingFactor, GroupInfo, NonceCommitment, ParticipantId, VSSCommitment


def encode_group_commitments(commitments: list[NonceCommitment], encoding: Encoding) -> bytes:
    """
    Encodes a list of NonceCommitments into bytes.
    """
    # Sort by participant id for deterministic encoding
    group_commitments = sorted(commitments, key=lambda c: c.participant_id)

    encoded_group_commitment = b""

    for commitment in group_commitments:
        encoded_commitment = encoding.encode_scalar(commitment.participant_id) + encoding.encode_point(
            commitment.hiding_nonce_commitment) + encoding.encode_point(commitment.binding_nonce_commitment)
        encoded_group_commitment = encoded_group_commitment + encoded_commitment

    return encoded_group_commitment


def compute_binding_factors(group_public_key: bytes, commitments: list[NonceCommitment], message: bytes, hashing: FrostHashing, encoding: Encoding) -> list[BindingFactor]:
    """
    Computes the binding factors for a signing session given the group public key, the list of NonceCommitments, and the message.
    """
    message_hash = hashing.h4(message)
    encoded_commitments_hash = hashing.h5(encode_group_commitments(commitments, encoding))

    rho_prefix = group_public_key + message_hash + encoded_commitments_hash

    binding_factors = []
    for commitment in commitments:
        rho_input = rho_prefix + encoding.encode_scalar(commitment.participant_id)
        binding_factor = hashing.h1(rho_input)
        binding_factors.append(BindingFactor(commitment.participant_id, binding_factor))
    return binding_factors


def binding_factor_for_participant(participant_id: ParticipantId, binding_factors: list[BindingFactor]) -> int:
    """
    Retrieves the binding factor for a given participant id from a list of BindingFactors.
    """
    for factor in binding_factors:
        if factor.participant_id == participant_id:
            return factor.binding_factor

    raise ValueError(f"binding factor not found for participant {participant_id}")


# EdwardsCurve for now, because this project only implements FROST for EdDSA, but this can be made more generic if needed.
def compute_group_commitment(commitments: list[NonceCommitment], binding_factors: list[BindingFactor], curve: EdwardsCurve) -> Tuple:
    """
    Computes the group commitment from a list of NonceCommitments and BindingFactors.
    """
    group_commitment = (0, 1, 1, 0)  # Neutral element in extended coordinates

    for commitment in commitments:
        binding_factor = binding_factor_for_participant(commitment.participant_id, binding_factors)
        binding_nonce = curve.scalar_mult(binding_factor, curve.affine_to_extended(commitment.binding_nonce_commitment))

        group_commitment = curve.add(group_commitment, curve.affine_to_extended(commitment.hiding_nonce_commitment))
        group_commitment = curve.add(group_commitment, binding_nonce)

    return curve.extended_to_affine(group_commitment)


def check_participant_bounds(threshold: int, participant_ids: list[ParticipantId], scalar_ops: ScalarOps) -> None:
    """
    Checks that participant ids are within valid bounds
    """
    if threshold <= 0:
        raise ValueError("threshold must be positive")
    if len(participant_ids) < threshold:
        raise ValueError("number of participants must be >= threshold")
    if len(participant_ids) <= 0:
        raise ValueError("number of participants must be positive")
    if len(participant_ids) >= scalar_ops.order:
        raise ValueError("number of participants must be less than the curve order")

    unique_ids = set(participant_ids)
    if len(unique_ids) != len(participant_ids):
        raise ValueError("participant ids must be unique")


def derive_group_info(threshold: int, max_participants: int, vss_commitment: list[VSSCommitment], curve: EdwardsCurve) -> GroupInfo:
    group_public_key = curve.encode_extended_point(vss_commitment[0])  # the first commitment is the group public key

    participant_public_keys: dict[ParticipantId, bytes] = {}

    for i in range(1, max_participants + 1):
        participant_i_pk = (0, 1, 1, 0)
        for j in range(0, threshold):
            participant_i_pk = curve.add(curve.scalar_mult(pow(i, j), vss_commitment[j]), participant_i_pk)
        participant_public_keys[i] = curve.encode_extended_point(participant_i_pk)
    return GroupInfo(group_public_key, participant_public_keys)
