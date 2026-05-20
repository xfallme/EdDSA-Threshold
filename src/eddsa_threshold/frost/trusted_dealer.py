from typing import Any, Tuple

from eddsa_threshold.eddsa.curves.base.edwards_curve import EdwardsCurve
from eddsa_threshold.frost.core.base.frost_hashing import FrostHashing
from eddsa_threshold.frost.core.secrets.shamir_secret_sharing import ShamirSecretSharing
from eddsa_threshold.frost.core.frost_types import GroupInfo, ParticipantId, SecretShare


class FrostTrustedDealer:
    
    def __init__(self, seed: int, threshold: int, participant_ids: list[ParticipantId], hashing: FrostHashing, curve: EdwardsCurve) -> None:
        if seed < 0 or seed >= curve.scalar_ops.order:
            raise ValueError("seed must be a valid scalar value for the curve")
        if threshold <= 0:
            raise ValueError("threshold must be positive")
        if len(participant_ids) < threshold:
            raise ValueError("number of participants must be >= threshold")

        unique_ids = set(participant_ids)
        if len(unique_ids) != len(participant_ids):
            raise ValueError("participant ids must be unique")
        
        self.seed = seed
        self.threshold = threshold
        self.participant_ids = participant_ids
        self.hashing = hashing
        self.curve = curve
        
        self.secret_sharing = ShamirSecretSharing(threshold, len(self.participant_ids), self.curve.scalar_ops)

    def keygen(self) -> Tuple[list[SecretShare], GroupInfo, Any]:
        """
        Trusted dealer key generation.
        """

        shares = self.secret_sharing.split(self.seed)
        group_public_key = self.curve.scalar_mult(self.seed, None) # None means base point

        group_info = GroupInfo(self.curve.encode_extended_point(group_public_key), {})
        
        self.seed = -1  # clear seed from memory after key generation, MUST not be reused for another keygen session

        return shares, group_info, Any  # TODO VSS commitments
    
    @classmethod
    def from_private_bytes(cls, seed: int, threshold: int, participant_ids: list[ParticipantId], hashing: FrostHashing, curve: EdwardsCurve) -> FrostTrustedDealer: 
        """Create a dealer instance from the given private seed bytes."""
        return cls(seed, threshold, participant_ids, hashing, curve)

    @classmethod
    def generate(cls, threshold: int, participant_ids: list[ParticipantId], hashing: FrostHashing, curve: EdwardsCurve) -> FrostTrustedDealer: 
        """Generate a new dealer instance with a fresh secret."""
        seed = curve.scalar_ops.random_scalar()
        return cls(seed, threshold, participant_ids, hashing, curve)