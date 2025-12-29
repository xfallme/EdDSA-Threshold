import os
from eddsa.curves.ed25519.ed25519_curve import Ed25519Curve
from eddsa.keys.keypair import Keypair
from eddsa.curves.ed25519.constants import SEED_SIZE
from eddsa.util.hash_bindings import sha512


class Ed25519Keypair(Keypair):
    """
    Ed25519 keypair implementation.

    Provides methods to create an Ed25519 keypair from a private seed or to generate a fresh random keypair.
    """

    @classmethod
    def from_private_bytes(cls, seed: bytes) -> Keypair:
        """Create Ed25519 keypair from 32-byte seed."""
        if len(seed) != SEED_SIZE:
            raise ValueError(f"Invalid seed size: {len(seed)} bytes (expected {SEED_SIZE} bytes)")

        # Derive key according to RFC 8032 Section 5.1.5
        # 1. Hash with SHA-512
        hashed = sha512(seed)

        # 2. Prune bits
        a_bytes = bytearray(hashed[:32])
        a_bytes[0] &= 248
        a_bytes[31] &= 127
        a_bytes[31] |= 64

        # 3. Convert to integer scalar
        scalar = int.from_bytes(a_bytes, byteorder='little')
        
        # 4. Compute prefix
        prefix = hashed[32:]

        # 5. Compute public key
        curve = Ed25519Curve()
        public_bytes = curve.encode_extended_point(curve.scalar_mult(scalar))

        return cls(seed, scalar, prefix, public_bytes)

    @classmethod
    def generate(cls) -> Keypair:
        """Generate a fresh Ed25519 keypair from a random 32-byte seed."""
        return cls.from_private_bytes(os.urandom(SEED_SIZE))
