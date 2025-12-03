from typing import Callable
from eddsa.algorithms.ed25519 import Ed25519
from eddsa.curves.ed25519.ed25519_curve import Ed25519Curve
from eddsa.curves.ed25519.scalar_ops import Ed25519ScalarOps
from eddsa.keys.keypair import Keypair
from eddsa.util.dom import dom2
from eddsa.util.hash_bindings import sha512


class Ed25519PH(Ed25519):
    """
    EdDSA using the Ed25519 curve and pre-hashing.
    Implements signing and verification methods.
    """

    @staticmethod
    def sign(message: bytes, keypair: Keypair, context: bytes = b"") -> bytes:
        """Sign a message using the provided Ed25519 keypair. Uses pre-hashing and context (set to empty by default)."""

        return Ed25519PH._sign(message, keypair, ph=sha512, dom2=dom2(1, context))
    
    @staticmethod
    def verify(signature: bytes, message: bytes, public_key: bytes, context: bytes = b"") -> bool:
        """Verify a signature for a message using the provided Ed25519 public key. Uses pre-hashing and context (set to empty by default)."""
        
        return Ed25519PH._verify(signature, message, public_key, ph=sha512, dom2=dom2(1, context))
