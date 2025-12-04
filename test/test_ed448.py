import binascii
import pytest

from eddsa.algorithms.ed448 import Ed448
from eddsa.algorithms.ed448ph import Ed448PH
from eddsa.keys.ed448_keypair import Ed448Keypair
from test_cases_eddsa_vectors import *


@pytest.mark.parametrize("lines", [case_ed448_test_vectors_rfc8032()], ids=["Ed448 RFC8032"])
def test_ed448_signature(lines, request):
    print(f"Running with {len(lines)} inputs for test '{request.node.callspec.id}'")

    for line in lines:
        x = line.split(':')

        sk = binascii.unhexlify(x[0])
        keypair = Ed448Keypair.from_private_bytes(sk)
        pk = binascii.unhexlify(x[1])
        assert keypair.public_bytes() == pk, "Derived public key does not match expected public key"

        m = binascii.unhexlify(x[2])
        ctx = binascii.unhexlify(x[3])
        s = binascii.unhexlify(x[4])

        # Sign the message
        generated_s = Ed448.sign(m, keypair, ctx)
        assert generated_s == s, "Generated signature does not match expected signature"

        # Verify the signature
        is_valid = Ed448.verify(s, m, keypair.public_bytes(), ctx)
        assert is_valid, "Signature verification failed"


@pytest.mark.parametrize("lines", [case_ed448ph_test_vectors_rfc8032()], ids=["Ed448PH RFC8032"])
def test_ed448ph_signature(lines, request):
    print(f"Running with {len(lines)} inputs for test '{request.node.callspec.id}'")

    for line in lines:
        x = line.split(':')

        sk = binascii.unhexlify(x[0])
        keypair = Ed448Keypair.from_private_bytes(sk)
        pk = binascii.unhexlify(x[1])
        assert keypair.public_bytes() == pk, "Derived public key does not match expected public key"

        m = binascii.unhexlify(x[2])
        ctx = binascii.unhexlify(x[3])
        s = binascii.unhexlify(x[4])

        # Sign the message
        generated_s = Ed448PH.sign(m, keypair, ctx)
        assert generated_s == s, "Generated signature does not match expected signature"

        # Verify the signature
        is_valid = Ed448PH.verify(s, m, keypair.public_bytes(), ctx)
        assert is_valid, "Signature verification failed"
