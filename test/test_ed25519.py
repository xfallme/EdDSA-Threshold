import binascii
import pytest
from eddsa.algorithms.ed25519 import Ed25519
from eddsa.keys.ed25519_keypair import Ed25519Keypair
from test_cases_eddsa_vectors import *


@pytest.mark.parametrize("lines", [case_ed25519_test_vectors_cr_yp_to()], ids=["Ed25519 Test Vectors from cr.yp.to"])
def test_ed25519_signature(lines, request):
    print(f"Running with {len(lines)} inputs for test '{request.node.callspec.id}'")

    for line in lines:
        x = line.split(':')

        # First 64 hex chars are the secret key, the rest is the public key
        sk = binascii.unhexlify(x[0][0:64])
        keypair = Ed25519Keypair.from_private_bytes(sk)

        m = binascii.unhexlify(x[2])
        sm = binascii.unhexlify(x[3])

        # Sign the message
        s = Ed25519.sign(m, keypair)
        assert (s+m) == sm, "Generated signature does not match expected signature"

        # Verify the signature
        is_valid = Ed25519.verify(s, m, keypair.public_bytes())
        assert is_valid, "Signature verification failed"
