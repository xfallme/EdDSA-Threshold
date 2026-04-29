from dataclasses import dataclass, field
from typing import Any

ParticipantId = int
SessionId = str


@dataclass(frozen=True)
class NonceCommitment:
    participant_id: ParticipantId
    hiding_commitment: Any
    binding_commitment: Any


@dataclass(frozen=True)
class BindingFactor:
    participant_id: ParticipantId
    binding_factor: int


@dataclass(frozen=True)
class SecretShare:
    index: ParticipantId  # x-coordinate
    value: int  # y = f(x) mod n


@dataclass(frozen=True)
class SigningPackage:
    session_id: SessionId
    message: bytes
    participant_ids: list[ParticipantId]
    commitments: dict[ParticipantId, NonceCommitment]


@dataclass
class SigningSession:
    session_id: SessionId
    message: bytes
    threshold: int
    participant_ids: set[ParticipantId]
    commitments: dict[ParticipantId, NonceCommitment] = field(default_factory=dict)
    signature_shares: dict[ParticipantId, int] = field(default_factory=dict)
    finalized: bool = False
