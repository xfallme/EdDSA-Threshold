from dataclasses import dataclass, field

from typing import Tuple

ParticipantId = int
SessionId = int
SecretValue = int


@dataclass(frozen=True)
class SecretShare:
    index: ParticipantId
    value: SecretValue


@dataclass(frozen=True)
class GroupInfo:
    group_public_key: bytes
    public_keys: dict[ParticipantId, Tuple[int, int]]


@dataclass(frozen=True)
class NonceCommitment:
    participant_id: ParticipantId
    hiding_nonce_commitment: Tuple[int, int]
    binding_nonce_commitment: Tuple[int, int]


@dataclass(frozen=True)
class BindingFactor:
    participant_id: ParticipantId
    binding_factor: int


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
    participant_ids: list[ParticipantId] = field(default_factory=list)
    commitments: dict[ParticipantId, NonceCommitment] = field(default_factory=dict)
    signature_shares: dict[ParticipantId, SecretValue] = field(default_factory=dict)
    signing_in_progress: bool = False
    round_one_completed: bool = False
    round_two_completed: bool = False
