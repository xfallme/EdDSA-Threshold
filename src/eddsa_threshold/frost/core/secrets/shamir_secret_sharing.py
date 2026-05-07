from eddsa_threshold.eddsa.curves.base.scalar_ops import ScalarOps
from eddsa_threshold.frost.core.polynomial import evaluate_polynomial, derive_interpolating_value
from eddsa_threshold.frost.core.secrets.secret_sharing import SecretSharing
from eddsa_threshold.frost.core.frost_types import SecretShare


class ShamirSecretSharing(SecretSharing):
    def __init__(self, threshold: int, num_shares: int, scalar_ops: ScalarOps):
        self.t = threshold
        self.n = num_shares
        self.scalar_ops = scalar_ops

    def split(self, secret: int) -> list[SecretShare]:
        """
        Split the secret into n shares with a threshold of t.
        Uses Shamir's Secret Sharing with random coefficients.
        """

        # Generate random coefficients for the polynomial f(x) = secret + a1*x + a2*x^2 + ... + a_{t-1}*x^{t-1}
        # Uses .random_scalar(), NOT PRODUCTION SECURE, but fine for this project.
        coeffs = [secret] + [self.scalar_ops.random_scalar() for _ in range(1, self.t)]

        shares = []
        for i in range(1, self.n + 1):
            secret_key_share_i = evaluate_polynomial(coeffs, i, self.scalar_ops)
            shares.append(SecretShare(i, secret_key_share_i))

        return shares

    def reconstruct(self, shares: list[SecretShare]) -> int:
        """
        Reconstruct the secret from at least t shares using Lagrange interpolation.
        """

        if len(shares) < self.t:
            raise ValueError("Not enough shares to reconstruct the secret")

        secret = 0
        for share_i in shares:
            # Add share_i contribution to the secret
            lagrange_coeff = derive_interpolating_value([share_j.index for share_j in shares], share_i.index, 0, self.scalar_ops)
            secret = self.scalar_ops.add(secret, self.scalar_ops.mul(share_i.value, lagrange_coeff))

        return secret
