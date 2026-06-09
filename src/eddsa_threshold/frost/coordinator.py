from eddsa_threshold.eddsa.curves.base.edwards_curve import EdwardsCurve
from eddsa_threshold.frost.core.base.frost_hashing import FrostHashing
from eddsa_threshold.frost.core.frost_types import GroupInfo, NonceCommitment, ParticipantId, SecretValue, SessionId, SigningPackage, SigningSession
from eddsa_threshold.frost.core.util import check_participant_bounds, compute_binding_factors, compute_group_commitment


class FrostCoordinator:
    """
    Coordinator-side implementation for a 2-round FROST signing flow.

    Cryptographic operations are delegated through callback hooks so this class can stay curve/algorithm agnostic.
    """

    def __init__(self, threshold: int, participant_ids: list[ParticipantId], group_info: GroupInfo, hashing: FrostHashing, curve: EdwardsCurve):
        if threshold <= 0:
            raise ValueError("threshold must be positive")

        check_participant_bounds(threshold, participant_ids, curve.scalar_ops)

        self.threshold = threshold
        self.participant_ids = participant_ids
        self.group_info = group_info

        self.hashing = hashing
        self.curve = curve

        self._signing_sessions: dict[SessionId, SigningSession] = {}

    def create_signing_session(self, message: bytes) -> SessionId:
        """
        Initializes a signing session for the given message.
        """

        # for now, session id is a hash of the message + randomness (allow for multiple signing sessions for the same message)
        session_id = self.hashing.h2(message) + self.curve.scalar_ops.random_scalar()

        signing_session = SigningSession(session_id, message)
        self._signing_sessions[session_id] = signing_session
        
        return session_id

    def register_participant_to_session(self, session_id: SessionId, participant_id: ParticipantId) -> None:
        """
        Registers a participant to a signing session.
        """

        if session_id not in self._signing_sessions:
            raise ValueError("signing session not found")

        signing_session = self._signing_sessions[session_id]

        if signing_session.signing_in_progress:
            raise ValueError("cannot register participant to session after signing has started")

        if participant_id not in self.participant_ids:
            raise ValueError("participant id not recognized")

        if participant_id in signing_session.participant_ids:
            raise ValueError("participant already registered to session")

        signing_session.participant_ids.append(participant_id)

    def start_signing_session(self, session_id: SessionId) -> None:
        """
        Marks the signing session as started, preventing further participant registrations.
        """

        if session_id not in self._signing_sessions:
            raise ValueError("signing session not found")

        signing_session = self._signing_sessions[session_id]

        if len(signing_session.participant_ids) < self.threshold:
            raise ValueError("not enough participants registered to start signing session")

        signing_session.signing_in_progress = True
        
    def receive_commitment(self, session_id: SessionId, participant_id: ParticipantId, commitment: NonceCommitment) -> None:
        """
        Receives a nonce commitment from a participant and stores it in the signing session.
        """

        if session_id not in self._signing_sessions:
            raise ValueError("signing session not found")

        signing_session = self._signing_sessions[session_id]

        if not signing_session.signing_in_progress:
            raise ValueError("signing session has not started yet")

        if participant_id not in signing_session.participant_ids:
            raise ValueError("participant id not registered to this signing session")

        if participant_id in signing_session.commitments:
            raise ValueError("commitment already received from this participant")

        signing_session.commitments[participant_id] = commitment
        
        if len(signing_session.commitments) == len(signing_session.participant_ids):
            signing_session.round_one_completed = True
            
    def create_signing_package(self, session_id: SessionId) -> SigningPackage:
        """
        Creates the signing package to be sent to the participants after round one is complete.
        """

        if session_id not in self._signing_sessions:
            raise ValueError("signing session not found")

        signing_session = self._signing_sessions[session_id]

        if not signing_session.round_one_completed:
            raise ValueError("round one not completed yet")

        return SigningPackage(session_id, signing_session.message, signing_session.participant_ids, signing_session.commitments)
    
    def receive_signature_share(self, session_id: SessionId, participant_id: ParticipantId, signature_share: SecretValue) -> None:
        """
        Receives a signature share from a participant and stores it in the signing session.
        """

        if session_id not in self._signing_sessions:
            raise ValueError("signing session not found")

        signing_session = self._signing_sessions[session_id]

        if not signing_session.round_one_completed:
            raise ValueError("round one not completed yet")

        if participant_id not in signing_session.participant_ids:
            raise ValueError("participant id not registered to this signing session")

        if participant_id in signing_session.signature_shares:
            raise ValueError("signature share already received from this participant")

        signing_session.signature_shares[participant_id] = signature_share
        
        if len(signing_session.signature_shares) == len(signing_session.participant_ids):
            signing_session.round_two_completed = True

    def aggregate(self, session_id: SessionId) -> bytes:
        """
        Aggregates the signature shares into a final signature.
        """
        
        if session_id not in self._signing_sessions:
            raise ValueError("signing session not found")
        
        signing_session = self._signing_sessions[session_id]
        
        if not signing_session.round_two_completed:
            raise ValueError("round two not completed yet")

        commitments = list(signing_session.commitments.values())
        signature_shares = list(signing_session.signature_shares.values())

        binding_factors = compute_binding_factors(self.group_info.group_public_key, commitments, signing_session.message, self.hashing, self.curve.encoding)

        group_commitment = compute_group_commitment(commitments, binding_factors, self.curve)

        z = 0
        for z_i in signature_shares:
            z = z + z_i

        z = self.curve.scalar_ops.reduce(z)

        return self.curve.encoding.encode_point(group_commitment) + self.curve.encoding.encode_scalar(z)
