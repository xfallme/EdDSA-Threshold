from typing import Callable
from eddsa.curves.ed448.ed448_curve import Ed448Curve
from eddsa.curves.ed448.scalar_ops import Ed448ScalarOps
from eddsa.keys.keypair import Keypair
from eddsa.util.dom import dom4
from eddsa.util.hash_bindings import shake256


class Ed448():
    """
    EdDSA using the Ed448 curve.
    Implements signing and verification methods.
    """

    @staticmethod
    def sign(message: bytes, keypair: Keypair, context: bytes) -> bytes:
        """Sign a message using the provided Ed448 keypair."""

        return Ed448._sign(message, keypair, ph=lambda m: m, dom4=dom4(0, context))

    @staticmethod
    def verify(signature: bytes, message: bytes, public_key: bytes, context: bytes) -> bool:
        """Verify a signature for a message using the provided Ed448 public key."""

        return Ed448._verify(signature, message, public_key, ph=lambda m: m, dom4=dom4(0, context))

    @staticmethod
    def _sign(message: bytes, keypair: Keypair, ph: Callable, dom4: bytes) -> bytes:
        """Internal sign method as basis for subclasses."""

        curve = Ed448Curve()
        scalar_ops = Ed448ScalarOps()

        # Sign message according to RFC 8032 Section 5.2.6
        # 1. Get precomputed prefix
        prefix = keypair.prefix

        # 2. Compute the nonce
        r = int.from_bytes(shake256(dom4 + prefix + ph(message), 114), byteorder='little')

        # 3. Compute the R point
        r = scalar_ops.reduce(r)
        R = curve.encode_extended_point(curve.scalar_mult(r))

        # 4. Compute the challenge
        k = int.from_bytes(shake256(dom4 + R + keypair.public_bytes + ph(message), 114), byteorder='little')

        # 5. Compute the S value
        k = scalar_ops.reduce(k)
        S = scalar_ops.reduce(r + k * keypair.scalar)

        return R + S.to_bytes(57, byteorder='little')

    @staticmethod
    def _verify(signature: bytes, message: bytes, public_key: bytes, ph: Callable, dom4: bytes) -> bool:
        """Internal verify method as basis for subclasses."""

        curve = Ed448Curve()
        scalar_ops = Ed448ScalarOps()

        # Verify signature according to RFC 8032 Section 5.2.7
        if len(signature) != 114:
            return False

        try:
            # 1. Decode R and S from the signature
            R = curve.decode_point(signature[:57])
            S = int.from_bytes(signature[57:], byteorder='little')
            if S >= scalar_ops.order or S < 0:
                return False
            
            A = curve.decode_point(public_key)
            
            # 2. Compute the challenge
            k = int.from_bytes(shake256(dom4 + signature[:57] + public_key + ph(message), 114), byteorder='little')
            k = scalar_ops.reduce(k)
            
            # 3. Verify the equation [S]B = R + [k]A
            left = curve.scalar_mult(S)
            right = curve.add(curve.affine_to_extended(R), curve.scalar_mult(k, curve.affine_to_extended(A)))
            
            return curve.extended_to_affine(left) == curve.extended_to_affine(right)

        except ValueError:
            return False
