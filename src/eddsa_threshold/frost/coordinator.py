from eddsa_threshold.eddsa.curves.base.edwards_curve import EdwardsCurve
from eddsa_threshold.frost.core.base.frost_hashing import FrostHashing
from eddsa_threshold.frost.core.secrets.shamir_secret_sharing import ShamirSecretSharing
from eddsa_threshold.frost.core.frost_types import GroupInfo, NonceCommitment, ParticipantId, SecretShare, SessionId, SigningPackage, SigningSession
from eddsa_threshold.frost.core.util import compute_binding_factors, compute_group_commitment


class FrostCoordinator:
    """
    Coordinator-side implementation for a 2-round FROST signing flow.

    Cryptographic operations are delegated through callback hooks so this class can stay curve/algorithm agnostic.
    """

    def __init__(self, threshold: int, participant_ids: list[ParticipantId], hashing: FrostHashing, curve: EdwardsCurve):
        if threshold <= 0:
            raise ValueError("threshold must be positive")
        if len(participant_ids) < threshold:
            raise ValueError("number of participants must be >= threshold")

        unique_ids = set(participant_ids)
        if len(unique_ids) != len(participant_ids):
            raise ValueError("participant ids must be unique")

        self.threshold = threshold
        self.participant_ids = unique_ids

        self.hashing = hashing
        self.curve = curve

    def aggregate(self, commitments: list[NonceCommitment], message: bytes, group_public_key: bytes, signature_shares: dict[ParticipantId, int]) -> bytes:
        """
        Aggregates the signature shares into a final signature.
        """

        binding_factors = compute_binding_factors(group_public_key, commitments, message, self.hashing, self.curve.encoding)

        group_commitment = compute_group_commitment(commitments, binding_factors, self.curve)

        z = 0
        for z_i in signature_shares.values():
            z = z + z_i

        z = self.curve.scalar_ops.reduce(z)

        return self.curve.encoding.encode_point(group_commitment) + self.curve.encoding.encode_scalar(z)
