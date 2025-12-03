from typing import Callable
from eddsa.algorithms.ed25519 import Ed25519
from eddsa.curves.ed25519.ed25519_curve import Ed25519Curve
from eddsa.curves.ed25519.scalar_ops import Ed25519ScalarOps
from eddsa.keys.keypair import Keypair
from eddsa.util.dom import dom2
from eddsa.util.hash_bindings import sha512


class Ed25519CTX():
    """
    EdDSA using the Ed25519 curve and context.
    Implements signing and verification methods.
    """

    @staticmethod
    def sign(message: bytes, keypair: Keypair, context: bytes = b"") -> bytes:
        """Sign a message using the provided Ed25519 keypair. Uses context (SHOULD not be emtpy)."""

        return Ed25519.__sign(message, keypair, ph=lambda m: m, dom2=dom2(0, context))
    
    @staticmethod
    def verify(signature: bytes, message: bytes, public_key: bytes, context: bytes = b"") -> bool:
        """Verify a signature for a message using the provided Ed25519 public key. Uses context (SHOULD not be emtpy)."""
        
        return Ed25519.__verify(signature, message, public_key, ph=lambda m: m, dom2=dom2(0, context))
