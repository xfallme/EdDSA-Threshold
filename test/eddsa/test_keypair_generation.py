import binascii
import pytest
from eddsa_threshhold.eddsa.keys.ed25519_keypair import Ed25519Keypair
from eddsa_threshhold.eddsa.keys.ed448_keypair import Ed448Keypair
from test_cases_eddsa_vectors import *


@pytest.mark.parametrize("lines", [case_ed25519_test_vectors_cr_yp_to()], ids=["Ed25519 Test Vectors from cr.yp.to"])
def test_keypair_generation_ed25519(lines, request):
    print(f"Running with {len(lines)} inputs for test '{request.node.callspec.id}'")
    for line in lines:
        x = line.split(':')
        # First 64 hex chars are the secret key, the rest is the public key
        sk = binascii.unhexlify(x[0][0:64])

        keypair = Ed25519Keypair.from_private_bytes(sk)
        pk = keypair.public_bytes

        assert x[0] == binascii.hexlify(sk + pk).decode('ascii'), "Secret key/Public key does not match expected value"
        assert x[1] == binascii.hexlify(pk).decode('ascii'), "Public key does not match expected value"


@pytest.mark.parametrize("lines", [case_ed448_test_vectors_rfc8032()], ids=["Ed448 Test Vectors from RFC8032"])
def test_keypair_generation_ed448(lines, request):
    print(f"Running with {len(lines)} inputs for test '{request.node.callspec.id}'")
    for line in lines:
        x = line.split(':')

        sk = binascii.unhexlify(x[0])

        keypair = Ed448Keypair.from_private_bytes(sk)
        pk = keypair.public_bytes

        assert x[0] == binascii.hexlify(sk).decode('ascii'), "Secret key does not match expected value"
        assert x[1] == binascii.hexlify(pk).decode('ascii'), "Public key does not match expected value"
