from typing import Callable
from eddsa.curves.ed25519.ed25519_curve import Ed25519Curve
from eddsa.curves.ed25519.scalar_ops import Ed25519ScalarOps
from eddsa.keys.ed25519_keypair import Ed25519Keypair
from eddsa.util.dom import dom2
from eddsa.util.hash_bindings import sha512


class Ed25519():
    """
    EdDSA using the Ed25519 curve.
    Implements signing and verification methods.
    """

    @staticmethod
    def sign(message: bytes, keypair: Ed25519Keypair) -> bytes:
        """Sign a message using the provided Ed25519 keypair."""

        return Ed25519._sign(message, keypair, ph=lambda m: m, dom2=dom2(0, None))
    
    @staticmethod
    def verify(signature: bytes, message: bytes, public_key: bytes) -> bool:
        """Verify a signature for a message using the provided Ed25519 public key."""
        
        return Ed25519._verify(signature, message, public_key, ph=lambda m: m, dom2=dom2(0, None))

    @staticmethod
    def _sign(message: bytes, keypair: Ed25519Keypair, ph: Callable, dom2: bytes) -> bytes:
        """Internal sign method as basis for subclasses."""

        curve = Ed25519Curve()
        scalar_ops = Ed25519ScalarOps()

        # Sign message according to RFC 8032 Section 5.1.6
        # 1. Get precomputed prefix
        prefix = keypair.prefix

        # 2. Compute the nonce
        r = int.from_bytes(sha512(dom2 + prefix + ph(message)), byteorder='little')

        # 3. Compute the R point
        r = scalar_ops.reduce(r)
        R = curve.encode_extended_point(curve.scalar_mult(r))

        # 4. Compute the challenge
        k = int.from_bytes(sha512(dom2 + R + keypair.public_bytes + ph(message)), byteorder='little')

        # 5. Compute the S value
        k = scalar_ops.reduce(k)
        S = scalar_ops.reduce(r + k * keypair.scalar)

        return R + S.to_bytes(32, byteorder='little')

    @staticmethod
    def _verify(signature: bytes, message: bytes, public_key: bytes, ph: Callable, dom2: bytes) -> bool:
        """Internal verify method as basis for subclasses."""

        curve = Ed25519Curve()
        scalar_ops = Ed25519ScalarOps()

        # Verify signature according to RFC 8032 Section 5.1.7
        if len(signature) != 64:
            return False

        try:
            # 1. Decode R and S from the signature
            R = curve.decode_point(signature[:32])
            S = int.from_bytes(signature[32:], byteorder='little')
            if S >= scalar_ops.order or S < 0:
                return False

            A = curve.decode_point(public_key)

            # 2. Compute the challenge
            k = int.from_bytes(sha512(dom2 + signature[:32] + public_key + ph(message)), byteorder='little')
            k = scalar_ops.reduce(k)

            # 3. Verify the equation [S]B = R + [k]A
            left = curve.scalar_mult(S)
            right = curve.add(curve.affine_to_extended(R), curve.scalar_mult(k, curve.affine_to_extended(A)))

            return curve.extended_to_affine(left) == curve.extended_to_affine(right)

        except ValueError:
            return False