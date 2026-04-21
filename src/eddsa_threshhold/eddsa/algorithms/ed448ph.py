from eddsa_threshhold.eddsa.algorithms.ed448 import Ed448
from eddsa_threshhold.eddsa.keys.ed448_keypair import Ed448Keypair
from eddsa_threshhold.eddsa.util.dom import dom4
from eddsa_threshhold.eddsa.util.hash_bindings import shake256


class Ed448PH(Ed448):
    """
    EdDSA using the Ed448 curve and pre-hashing.
    Implements signing and verification methods.
    """

    @staticmethod
    def sign(message: bytes, keypair: Ed448Keypair, context: bytes = b"") -> bytes:
        """Sign a message using the provided Ed448 keypair."""

        return Ed448PH._sign(message, keypair, ph=lambda m: shake256(m, 64), dom4=dom4(1, context))

    @staticmethod
    def verify(signature: bytes, message: bytes, public_key: bytes, context: bytes = b"") -> bool:
        """Verify a signature for a message using the provided Ed448 public key."""

        return Ed448PH._verify(signature, message, public_key, ph=lambda m: shake256(m, 64), dom4=dom4(1, context))
