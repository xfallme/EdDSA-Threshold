import os
from typing import Tuple

from eddsa_threshold.eddsa.curves.base.edwards_curve import EdwardsCurve
from eddsa_threshold.frost.core.base.frost_hashing import FrostHashing
from eddsa_threshold.frost.core.frost_types import GroupInfo, NonceCommitment, ParticipantId, SecretShare, SecretValue, SessionId, SigningPackage, VSSCommitment
from eddsa_threshold.frost.core.polynomial import derive_interpolating_value
from eddsa_threshold.frost.core.util import binding_factor_for_participant, compute_binding_factors, compute_group_commitment


class FrostParticipant:
    """
    Participant-side implementation for a 2-round FROST signing flow.

    The participant owns one long-term secret key share and ephemeral nonces.
    """

    # EdwardsCurve for now, because this project only implements FROST for EdDSA, but this can be made more generic if needed.
    def __init__(self, participant_id: ParticipantId, threshold: int, hashing: FrostHashing, curve: EdwardsCurve):
        self.participant_id = participant_id
        self.threshold = threshold

        self.hashing = hashing
        self.curve = curve

        self._nonce_pair: dict[SessionId, Tuple[int, int]] = dict()  # store nonce pairs for active signing sessions, cleared after signing is complete

    def set_and_verify_dealer_info(self, secret_share: SecretShare, group_info: GroupInfo, vss_commitment: list[VSSCommitment]):
        """
        Set the participant's secret share and group info after receiving and verifying them from the trusted dealer.
        """
        if not self._vss_verify(secret_share, vss_commitment):
            raise ValueError(f"VSS verification failed for the received secret share and VSS commitment for participant {self.participant_id}")

        self.secret_share = secret_share
        self.group_info = group_info

    def round_one_commit(self, session_id: SessionId) -> NonceCommitment:
        """
        Round 1 of FROST signing: generates a nonce pair and returns the corresponding commitment.
        """

        if session_id in self._nonce_pair:
            raise ValueError(f"participant {self.participant_id} has already committed to this signing session")

        nonce_pair, commitment = self._commit()
        self._nonce_pair[session_id] = nonce_pair

        return commitment

    def round_two_sign(self, signing_package: SigningPackage) -> SecretValue:
        """
        Round 2 of FROST signing: takes the signing package from the coordinator and returns the signature share.
        """

        if signing_package.session_id not in self._nonce_pair:
            raise ValueError(f"participant {self.participant_id} must commit to this signing session before signing")

        nonce_pair = self._nonce_pair[signing_package.session_id]
        signature_share = self._sign(signing_package.session_id, signing_package.message, list(signing_package.commitments.values()))

        self._nonce_pair.pop(signing_package.session_id)  # clear nonce pair for this session since signing is complete

        return signature_share

    def _commit(self) -> Tuple[Tuple[int, int], NonceCommitment]:
        encoded_secret_share = self.curve.encoding.encode_scalar(self.secret_share.value)
        hiding_nonce = self._generate_nonce(encoded_secret_share)
        binding_nonce = self._generate_nonce(encoded_secret_share)

        hiding_nonce_commitment = self.curve.extended_to_affine(self.curve.scalar_mult(hiding_nonce, None))  # None means base point
        binding_nonce_commitment = self.curve.extended_to_affine(self.curve.scalar_mult(binding_nonce, None))

        return (hiding_nonce, binding_nonce), NonceCommitment(self.secret_share.index, hiding_nonce_commitment, binding_nonce_commitment)

    def _sign(self, session_id: SessionId, message: bytes, commitments: list[NonceCommitment]) -> SecretValue:
        nonce_pair = self._nonce_pair[session_id]

        binding_factors = compute_binding_factors(self.group_info.group_public_key, commitments, message, self.hashing, self.curve.encoding)
        binding_factor = binding_factor_for_participant(self.secret_share.index, binding_factors)

        group_commitment = compute_group_commitment(commitments, binding_factors, self.curve)

        participants = list(commitment.participant_id for commitment in commitments)
        # Potentially implemenet reuse logic
        lambda_i = derive_interpolating_value(participants, self.secret_share.index, 0, self.curve.scalar_ops)

        challenge = self._compute_challenge(group_commitment, message)

        hiding_nonce, binding_nonce = nonce_pair
        signature_share = hiding_nonce + (binding_nonce * binding_factor) + (lambda_i * self.secret_share.value * challenge)

        return self.curve.scalar_ops.reduce(signature_share)

    def _vss_verify(self, secret_share: SecretShare, vss_commitment: list[VSSCommitment]) -> bool:
        """
        Verify a participant's secret share against the VSS commitment.
        """

        S = self.curve.scalar_mult(secret_share.value, None)
        S_ = (0, 1, 1, 0)  # identity point in extended coordinates
        for i in range(0, self.threshold):
            S_ = self.curve.add(S_, self.curve.scalar_mult(pow(secret_share.index, i), vss_commitment[i]))

        return self.curve.extended_to_affine(S) == self.curve.extended_to_affine(S_)

    def _generate_nonce(self, secret: bytes) -> int:
        """
        Generates a nonce using the participant's secret share and a random value.
        """
        random = os.urandom(32)
        return self.hashing.h3(random + secret)
    
    def _compute_challenge(self, group_commitment: Tuple, message: bytes) -> int:
        """
        Computes the signing challenge c = H(R || A || m) where R is the group commitment, A is the group public key, and m is the message.
        """
        challenge_input = self.curve.encoding.encode_point(group_commitment) + self.group_info.group_public_key + message
        return self.hashing.h2(challenge_input)