from eddsa_threshold.eddsa.curves.ed25519.constants import L
from eddsa_threshold.eddsa.util.hash_bindings import sha512
from eddsa_threshold.frost.core.base.frost_hashing import FrostHashing


class Ed25519FrostHashing(FrostHashing):
    """
    Ed25519FrostHashing is the implementation of the FrostHashing interface for Ed25519.
    """

    _CONTEXT_STRING = b"FROST-ED25519-SHA512-v1"

    def h1(self, m: bytes) -> int:
        return int.from_bytes(sha512(self._CONTEXT_STRING + b"rho" + m), "little") % L

    def h2(self, m: bytes) -> int:
        return int.from_bytes(sha512(m), "little") % L

    def h3(self, m: bytes) -> int:
        return int.from_bytes(sha512(self._CONTEXT_STRING + b"nonce" + m), "little") % L

    def h4(self, m: bytes) -> bytes:
        return sha512(self._CONTEXT_STRING + b"msg" + m)

    def h5(self, m: bytes) -> bytes:
        return sha512(self._CONTEXT_STRING + b"com" + m)
