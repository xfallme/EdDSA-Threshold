import os
from eddsa.curves.ed448.ed448_curve import Ed448Curve
from eddsa.keys.keypair import Keypair
from eddsa.curves.ed448.constants import SEED_SIZE
from eddsa.util.hash_bindings import shake256


class Ed448Keypair(Keypair):
    """
    Ed448 keypair implementation.

    Provides methods to create an Ed448 keypair from a private seed or to generate a fresh random keypair.
    """

    @classmethod
    def from_private_bytes(cls, seed: bytes) -> Keypair:
        """Create Ed448 keypair from 57-byte seed."""
        if len(seed) != SEED_SIZE:
            raise ValueError(f"Invalid seed size: {len(seed)} bytes (expected {SEED_SIZE} bytes)")

        # Derive key according to RFC 8032 Section 5.2.5
        # 1. Hash with SHAKE-256(x, 114)
        hashed = shake256(seed, 114)

        # 2. Prune bits
        a_bytes = bytearray(hashed[:57])
        a_bytes[0] &= 252
        a_bytes[56] &= 0
        a_bytes[55] |= 128

        # 3. Convert to integer scalar
        scalar = int.from_bytes(a_bytes, byteorder='little')

        # 4. Compute public key
        curve = Ed448Curve()
        public_bytes = curve.encode_extended_point(curve.scalar_mult(scalar))

        return cls(seed, scalar, public_bytes)

    @classmethod
    def generate(cls) -> Keypair:
        """Generate a fresh Ed448 keypair from a random 57-byte seed."""
        return cls.from_private_bytes(os.urandom(SEED_SIZE))
