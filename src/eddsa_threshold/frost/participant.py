from typing import Tuple

from eddsa_threshold.eddsa.curves.base.edwards_curve import EdwardsCurve
from eddsa_threshold.frost.core.base.frost_hashing import FrostHashing
from eddsa_threshold.frost.core.frost_types import GroupInfo, NonceCommitment, ParticipantId, SecretShare, SecretValue, SessionId, SigningPackage, VSSCommitment
from eddsa_threshold.frost.core.polynomial import derive_interpolating_value
from eddsa_threshold.frost.core.util import binding_factor_for_participant, compute_binding_factors, compute_challenge, compute_group_commitment, generate_nonce, participants_from_commitment_list


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
        if not self._vss_verify(self.threshold, secret_share, vss_commitment, self.curve):
            raise ValueError(f"VSS verification failed for the received secret share and VSS commitment for participant {self.participant_id}")
        
        self.secret_share = secret_share
        self.group_info = group_info

    def round_one_commit(self, session_id: SessionId) -> NonceCommitment:
        """
        Round 1 of FROST signing: generates a nonce pair and returns the corresponding commitment.
        """
        
        if session_id in self._nonce_pair:
            raise ValueError(f"participant {self.participant_id} has already committed to this signing session")
        
        nonce_pair, commitment = self._commit(self.secret_share, self.curve, self.hashing)
        self._nonce_pair[session_id] = nonce_pair

        return commitment

    def round_two_sign(self, signing_package: SigningPackage) -> SecretValue:
        """
        Round 2 of FROST signing: takes the signing package from the coordinator and returns the signature share.
        """
        
        if signing_package.session_id not in self._nonce_pair:
            raise ValueError(f"participant {self.participant_id} must commit to this signing session before signing")
        
        nonce_pair = self._nonce_pair[signing_package.session_id]
        signature_share = self._sign(signing_package.message, list(signing_package.commitments.values()), self.secret_share, nonce_pair, self.group_info, self.curve, self.hashing)
        
        self._nonce_pair.pop(signing_package.session_id)  # clear nonce pair for this session since signing is complete
        
        return signature_share

    @staticmethod
    def _commit(secret_share: SecretShare, curve: EdwardsCurve, hashing: FrostHashing) -> Tuple[Tuple[int, int], NonceCommitment]:
        encoded_secret_share = curve.encoding.encode_scalar(secret_share.value)
        hiding_nonce = generate_nonce(encoded_secret_share, hashing)
        binding_nonce = generate_nonce(encoded_secret_share, hashing)

        hiding_nonce_commitment = curve.extended_to_affine(curve.scalar_mult(hiding_nonce, None)) # None means base point
        binding_nonce_commitment = curve.extended_to_affine(curve.scalar_mult(binding_nonce, None))

        return (hiding_nonce, binding_nonce), NonceCommitment(secret_share.index, hiding_nonce_commitment, binding_nonce_commitment)

    @staticmethod
    def _sign(message: bytes, commitments: list[NonceCommitment], secret_share: SecretShare, nonce_pair: Tuple[int, int], group_info: GroupInfo, curve: EdwardsCurve, hashing: FrostHashing) -> SecretValue:
        binding_factors = compute_binding_factors(group_info.group_public_key, commitments, message, hashing, curve.encoding)
        binding_factor = binding_factor_for_participant(secret_share.index, binding_factors)

        group_commitment = compute_group_commitment(commitments, binding_factors, curve)

        participants = participants_from_commitment_list(commitments)
        # Potentially implemenet reuse logic
        lambda_i = derive_interpolating_value(participants, secret_share.index, 0, curve.scalar_ops)

        challenge = compute_challenge(group_commitment, group_info.group_public_key, message, hashing, curve.encoding)

        hiding_nonce, binding_nonce = nonce_pair
        signature_share = hiding_nonce + (binding_nonce * binding_factor) + (lambda_i * secret_share.value * challenge)

        return curve.scalar_ops.reduce(signature_share)
    
    @staticmethod
    def _vss_verify(threshold: int, secret_share: SecretShare, vss_commitment: list[VSSCommitment], curve: EdwardsCurve) -> bool:
        """
        Verify a participant's secret share against the VSS commitment.
        """
        
        S = curve.scalar_mult(secret_share.value, None)
        S_ = (0, 1, 1, 0)  # identity point in extended coordinates
        for i in range(0, threshold):
            S_ = curve.add(S_, curve.scalar_mult(pow(secret_share.index, i), vss_commitment[i]))
            
        return curve.extended_to_affine(S) == curve.extended_to_affine(S_)
