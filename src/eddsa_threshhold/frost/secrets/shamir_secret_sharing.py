from eddsa_threshhold.eddsa.curves.base.scalar_ops import ScalarOps
from eddsa_threshhold.frost.secrets.secret_sharing import SecretSharing
from eddsa_threshhold.frost.types.secrets import SecretShare


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
            # Evaluate f(i) to get the share value
            secret_key_share_i = 0
            for coeff in reversed(coeffs):
                secret_key_share_i *= i
                secret_key_share_i = self.scalar_ops.add(secret_key_share_i, coeff)
            shares.append(SecretShare(index=i, value=secret_key_share_i))

        return shares

    def reconstruct(self, shares: list[SecretShare]) -> int:
        """
        Reconstruct the secret from at least t shares using Lagrange interpolation.
        """

        if len(shares) < self.t:
            raise ValueError("Not enough shares to reconstruct the secret")

        secret = 0
        for i, share_i in enumerate(shares):
            # Compute the Lagrange basis polynomial for share_i
            numerator = 1
            denominator = 1
            for j, share_j in enumerate(shares):
                if j != i:
                    numerator = self.scalar_ops.mul(numerator, -share_j.index)
                    denominator = self.scalar_ops.mul(denominator, share_i.index - share_j.index)

            # Add share_i contribution to the secret
            lagrange_coeff = self.scalar_ops.mul(numerator, self.scalar_ops.inv(denominator))
            secret = self.scalar_ops.add(secret, self.scalar_ops.mul(share_i.value, lagrange_coeff))

        return secret
