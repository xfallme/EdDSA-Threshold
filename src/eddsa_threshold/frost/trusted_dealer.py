from typing import Callable, Final

from eddsa_threshold.eddsa.curves.base.edwards_curve import EdwardsCurve
from eddsa_threshold.frost.core.base.frost_hashing import FrostHashing
from eddsa_threshold.frost.core.secrets.shamir_secret_sharing import ShamirSecretSharing
from eddsa_threshold.frost.core.frost_types import ParticipantId, SecretShare, VSSCommitment
from eddsa_threshold.frost.core.util import check_participant_bounds


class FrostTrustedDealer:
    
    def __init__(self, seed: int, threshold: int, participant_ids: list[ParticipantId], participant_connections: dict[ParticipantId, Callable[[SecretShare, list[VSSCommitment]], None]], curve: EdwardsCurve) -> None:
        if seed < 0 or seed >= curve.scalar_ops.order:
            raise ValueError("seed must be a valid scalar value for the curve")
        
        check_participant_bounds(threshold, participant_ids, curve.scalar_ops)
        
        self._seed = seed
        self.PARTICIPANT_IDS: Final[list[ParticipantId]] = participant_ids
        self._PARTICIPANT_CONNECTIONS: Final[dict[ParticipantId, Callable[[SecretShare, list[VSSCommitment]], None]]] = participant_connections
        self._CURVE: Final[EdwardsCurve] = curve
        
        # In the future, we may want to support other secret sharing schemes
        self._SECRET_SHARING: Final[ShamirSecretSharing] = ShamirSecretSharing(threshold, len(self.PARTICIPANT_IDS), self._CURVE.scalar_ops)

    def keygen(self):
        """
        Trusted dealer key generation.
        """

        shares, coeffs = self._SECRET_SHARING.split(self._seed)

        vss_commitment = self._vss_commit(coeffs)
        
        for participant_id, share in zip(self.PARTICIPANT_IDS, shares):
            if participant_id in self._PARTICIPANT_CONNECTIONS:
                self._PARTICIPANT_CONNECTIONS[participant_id](share, vss_commitment)
            else:
                raise ValueError(f"No connection provided for participant {participant_id}")
            
        # clear seed, shares, coeffs from memory after key generation, MUST not be reused for another keygen session
        self._seed = -1
        shares.clear()
        coeffs.clear()
    
    @classmethod
    def from_private_bytes(cls, seed: int, threshold: int, participant_ids: list[ParticipantId], participant_connections: dict[ParticipantId, Callable[[SecretShare, list[VSSCommitment]], None]], curve: EdwardsCurve) -> FrostTrustedDealer: 
        """Create a dealer instance from the given private seed bytes."""
        return cls(seed, threshold, participant_ids, participant_connections, curve)

    @classmethod
    def generate(cls, threshold: int, participant_ids: list[ParticipantId], participant_connections: dict[ParticipantId, Callable[[SecretShare, list[VSSCommitment]], None]], curve: EdwardsCurve) -> FrostTrustedDealer: 
        """Generate a new dealer instance with a fresh secret."""
        seed = curve.scalar_ops.random_scalar()
        return cls(seed, threshold, participant_ids, participant_connections, curve)
    
    def _vss_commit(self, coeffs: list[int]) -> list[VSSCommitment]:
        vss_commitment = []
        
        for coeff in coeffs:
            vss_i = self._CURVE.scalar_mult(coeff, None) 
            vss_commitment.append(vss_i)
            
        return vss_commitment