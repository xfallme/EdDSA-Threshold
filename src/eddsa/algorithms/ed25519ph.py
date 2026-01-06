from eddsa.algorithms.ed25519 import Ed25519
from eddsa.keys.ed25519_keypair import Ed25519Keypair
from eddsa.util.dom import dom2
from eddsa.util.hash_bindings import sha512


class Ed25519PH(Ed25519):
    """
    EdDSA using the Ed25519 curve and pre-hashing.
    Implements signing and verification methods.
    """

    @staticmethod
    def sign(message: bytes, keypair: Ed25519Keypair, context: bytes = b"") -> bytes:
        """Sign a message using the provided Ed25519 keypair. Uses pre-hashing and context (set to empty by default)."""

        return Ed25519PH._sign(message, keypair, ph=sha512, dom2=dom2(1, context))
    
    @staticmethod
    def verify(signature: bytes, message: bytes, public_key: bytes, context: bytes = b"") -> bool:
        """Verify a signature for a message using the provided Ed25519 public key. Uses pre-hashing and context (set to empty by default)."""
        
        return Ed25519PH._verify(signature, message, public_key, ph=sha512, dom2=dom2(1, context))
