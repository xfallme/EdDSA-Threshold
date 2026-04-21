from itertools import combinations

import pytest
from pytest_cases import parametrize_with_cases

from eddsa_threshhold.eddsa.curves.base.scalar_ops import ScalarOps
from eddsa_threshhold.frost.core.shamir_secret_sharing import ShamirSecretSharing


@parametrize_with_cases("scalar_ops", cases="test_cases_scalars")
def test_basic_shamir_secret_sharing(scalar_ops: ScalarOps):
    """Test that Shamir's Secret Sharing correctly splits and reconstructs a secret."""
    sss = ShamirSecretSharing(threshold=3, num_shares=5, scalar_ops=scalar_ops)

    secret = 123456789012345678901234567890
    shares = sss.split(secret)

    # Test that we can't reconstruct the secret from fewer than t shares
    for i in range(1, sss.t):
        for subset in combinations(shares, i):
            with pytest.raises(ValueError):
                reconstructed = sss.reconstruct(list(subset))

    # Test that we can reconstruct the secret from any t+ shares
    for i in range(sss.t, sss.n + 1):
        for subset in combinations(shares, i):
            reconstructed = sss.reconstruct(list(subset))
            assert reconstructed == secret, f"Failed to reconstruct secret from shares: {subset}"
