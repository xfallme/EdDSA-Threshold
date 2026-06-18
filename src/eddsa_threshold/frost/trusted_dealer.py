from typing import Callable

from eddsa_threshold.eddsa.curves.base.edwards_curve import EdwardsCurve
from eddsa_threshold.frost.core.base.frost_hashing import FrostHashing
from eddsa_threshold.frost.core.secrets.shamir_secret_sharing import ShamirSecretSharing
from eddsa_threshold.frost.core.frost_types import ParticipantId, SecretShare, VSSCommitment
from eddsa_threshold.frost.core.util import check_participant_bounds


class FrostTrustedDealer:
    
    def __init__(self, seed: int, threshold: int, participant_ids: list[ParticipantId], participant_connections: dict[ParticipantId, Callable[[SecretShare, list[VSSCommitment]], None]], hashing: FrostHashing, curve: EdwardsCurve) -> None:
        if seed < 0 or seed >= curve.scalar_ops.order:
            raise ValueError("seed must be a valid scalar value for the curve")
        
        check_participant_bounds(threshold, participant_ids, curve.scalar_ops)
        
        self.seed = seed
        self.threshold = threshold
        self.participant_ids = participant_ids
        self.participant_connections = participant_connections
        self.hashing = hashing
        self.curve = curve
        
        # In the future, we may want to support other secret sharing schemes
        self.secret_sharing = ShamirSecretSharing(threshold, len(self.participant_ids), self.curve.scalar_ops)

    def keygen(self):
        """
        Trusted dealer key generation.
        """

        shares, coeffs = self.secret_sharing.split(self.seed)

        vss_commitment = self._vss_commit(coeffs)
        
        for participant_id, share in zip(self.participant_ids, shares):
            if participant_id in self.participant_connections:
                self.participant_connections[participant_id](share, vss_commitment)
            else:
                raise ValueError(f"No connection provided for participant {participant_id}")
            
        # clear seed, shares, coeffs from memory after key generation, MUST not be reused for another keygen session
        self.seed = -1
        shares.clear()
        coeffs.clear()
    
    @classmethod
    def from_private_bytes(cls, seed: int, threshold: int, participant_ids: list[ParticipantId], participant_connections: dict[ParticipantId, Callable[[SecretShare, list[VSSCommitment]], None]], hashing: FrostHashing, curve: EdwardsCurve) -> FrostTrustedDealer: 
        """Create a dealer instance from the given private seed bytes."""
        return cls(seed, threshold, participant_ids, participant_connections, hashing, curve)

    @classmethod
    def generate(cls, threshold: int, participant_ids: list[ParticipantId], participant_connections: dict[ParticipantId, Callable[[SecretShare, list[VSSCommitment]], None]], hashing: FrostHashing, curve: EdwardsCurve) -> FrostTrustedDealer: 
        """Generate a new dealer instance with a fresh secret."""
        seed = curve.scalar_ops.random_scalar()
        return cls(seed, threshold, participant_ids, participant_connections, hashing, curve)
    
    def _vss_commit(self, coeffs: list[int]) -> list[VSSCommitment]:
        vss_commitment = []
        
        for coeff in coeffs:
            vss_i = self.curve.scalar_mult(coeff, None) 
            vss_commitment.append(vss_i)
            
        return vss_commitment