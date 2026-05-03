from typing import Tuple

from eddsa_threshhold.eddsa.curves.base.edwards_curve import EdwardsCurve
from eddsa_threshhold.frost.core.base.frost_hashing import FrostHashing
from eddsa_threshhold.frost.coordinator import ParticipantId, SessionId
from eddsa_threshhold.frost.core.polynomial import derive_interpolating_value
from eddsa_threshhold.frost.core.types import GroupInfo, NonceCommitment, SecretShare, SigningPackage
from eddsa_threshhold.frost.core.util import binding_factor_for_participant, compute_binding_factors, compute_challenge, compute_group_commitment, generate_nonce, participants_from_commitment_list


class FrostParticipant:
    """
    Participant-side for a 2-round FROST signing flow.

    The participant owns one long-term secret key share and ephemeral nonces.
    """

    # EdwardsCurve for now, because this project only implements FROST for EdDSA, but this can be made more generic if needed.
    def __init__(self, participant_id: ParticipantId, secret_key_share: SecretShare, group_info: GroupInfo, hashing: FrostHashing, curve: EdwardsCurve):
        self.participant_id = participant_id
        self.secret_share = secret_key_share
        self.group_info = group_info

        self.hashing = hashing
        self.curve = curve

        self._active_session_id: SessionId | None = None  # TODO
        self._nonce_pair: Tuple[int, int] | None = None

    def round_one_commit(self) -> NonceCommitment:
        """
        Round 1 of FROST signing: generates a nonce pair and returns the corresponding commitment.
        """
        # TODO: check various preconditions (e.g. active session, etc.)
        return self._commit()

    def round_two_sign(self, signing_package: SigningPackage) -> int:
        """
        Round 2 of FROST signing: takes the signing package from the coordinator and returns the signature share.
        """
        # TODO: check various preconditions (e.g. active session, etc.)
        signature_share = self._sign(signing_package.message, list(signing_package.commitments.values()))
        
        self._nonce_pair = None  # clear nonces from memory after signing, MUST not be reused for another signing session
        
        return signature_share

    def _commit(self) -> NonceCommitment:
        encoded_secret_share = self.curve.encoding.encode_scalar(self.secret_share.value)
        hiding_nonce = generate_nonce(encoded_secret_share, self.hashing)
        binding_nonce = generate_nonce(encoded_secret_share, self.hashing)
        
        hiding_nonce_commitment = self.curve.extended_to_affine(self.curve.scalar_mult(hiding_nonce, None)) # None means base point
        binding_nonce_commitment = self.curve.extended_to_affine(self.curve.scalar_mult(binding_nonce, None))

        self._nonce_pair = (hiding_nonce, binding_nonce)

        return NonceCommitment(self.participant_id, hiding_nonce_commitment, binding_nonce_commitment)

    def _sign(self, message: bytes, commitments: list[NonceCommitment]) -> int:
        if self._nonce_pair is None:
            raise ValueError("participant must commit before signing")

        binding_factors = compute_binding_factors(self.group_info.group_public_key, commitments, message, self.hashing, self.curve.encoding)
        binding_factor = binding_factor_for_participant(self.participant_id, binding_factors)

        group_commitment = compute_group_commitment(commitments, binding_factors, self.curve)

        participants = participants_from_commitment_list(commitments)
        # Potentially implemenet reuse logic
        lambda_i = derive_interpolating_value(participants, self.participant_id, 0, self.curve.scalar_ops)

        challenge = compute_challenge(group_commitment, self.group_info.group_public_key, message, self.hashing, self.curve.encoding)

        hiding_nonce, binding_nonce = self._nonce_pair
        signature_share = hiding_nonce + (binding_nonce * binding_factor) + (lambda_i * self.secret_share.value * challenge)

        return self.curve.scalar_ops.reduce(signature_share)
