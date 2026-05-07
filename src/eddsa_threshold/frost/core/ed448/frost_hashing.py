from eddsa_threshold.eddsa.curves.ed448.constants import L
from eddsa_threshold.eddsa.util.hash_bindings import shake256
from eddsa_threshold.frost.core.base.frost_hashing import FrostHashing


class Ed448FrostHashing(FrostHashing):
    """
    Ed448FrostHashing is the implementation of the FrostHashing interface for Ed448.
    """
    
    _CONTEXT_STRING = b"FROST-ED448-SHAKE256-v1"
    _DIGEST_SIZE = 114

    def h1(self, m: bytes) -> int:
        return int.from_bytes(shake256(self._CONTEXT_STRING + b"rho" + m, self._DIGEST_SIZE), "little") % L

    def h2(self, m: bytes) -> int:
        return int.from_bytes(shake256(b"SigEd448" + b'\x00' + b'\x00' + m, self._DIGEST_SIZE), "little") % L

    def h3(self, m: bytes) -> int:
        return int.from_bytes(shake256(self._CONTEXT_STRING + b"nonce" + m, self._DIGEST_SIZE), "little") % L

    def h4(self, m: bytes) -> bytes:
        return shake256(self._CONTEXT_STRING + b"msg" + m, self._DIGEST_SIZE)

    def h5(self, m: bytes) -> bytes:
        return shake256(self._CONTEXT_STRING + b"com" + m, self._DIGEST_SIZE)