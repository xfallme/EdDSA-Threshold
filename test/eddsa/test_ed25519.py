import binascii
import pytest
from eddsa.algorithms.ed25519 import Ed25519
from eddsa.algorithms.ed25519ctx import Ed25519CTX
from eddsa.algorithms.ed25519ph import Ed25519PH
from eddsa.keys.ed25519_keypair import Ed25519Keypair
from test_cases_eddsa_vectors import *


@pytest.mark.parametrize("lines", [case_ed25519_test_vectors_cr_yp_to(), case_ed25519_test_vectors_rfc8032()], ids=["Ed25519 cr.yp.to", "Ed25519 RFC8032"])
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
        is_valid = Ed25519.verify(s, m, keypair.public_bytes)
        assert is_valid, "Signature verification failed"


@pytest.mark.parametrize("lines", [case_ed25519ctx_test_vectors_rfc8032()], ids=["Ed25519CTX RFC8032"])
def test_ed25519ctx_signature(lines, request):
    print(f"Running with {len(lines)} inputs for test '{request.node.callspec.id}'")

    for line in lines:
        x = line.split(':')

        sk = binascii.unhexlify(x[0])
        keypair = Ed25519Keypair.from_private_bytes(sk)
        pk = binascii.unhexlify(x[1])
        assert keypair.public_bytes == pk, "Derived public key does not match expected public key"

        m = binascii.unhexlify(x[2])
        ctx = binascii.unhexlify(x[3])
        s = binascii.unhexlify(x[4])

        # Sign the message
        generated_s = Ed25519CTX.sign(m, keypair, ctx)
        assert generated_s == s, "Generated signature does not match expected signature"

        # Verify the signature
        is_valid = Ed25519CTX.verify(s, m, keypair.public_bytes, ctx)
        assert is_valid, "Signature verification failed"


@pytest.mark.parametrize("lines", [case_ed25519ph_test_vectors_rfc8032()], ids=["Ed25519PH RFC8032"])
def test_ed25519ph_signature(lines, request):
    print(f"Running with {len(lines)} inputs for test '{request.node.callspec.id}'")

    for line in lines:
        x = line.split(':')

        sk = binascii.unhexlify(x[0])
        keypair = Ed25519Keypair.from_private_bytes(sk)
        pk = binascii.unhexlify(x[1])
        assert keypair.public_bytes == pk, "Derived public key does not match expected public key"

        m = binascii.unhexlify(x[2])
        ctx = binascii.unhexlify(x[3])
        s = binascii.unhexlify(x[4])

        # Sign the message
        generated_s = Ed25519PH.sign(m, keypair, ctx)
        assert generated_s == s, "Generated signature does not match expected signature"

        # Verify the signature
        is_valid = Ed25519PH.verify(s, m, keypair.public_bytes, ctx)
        assert is_valid, "Signature verification failed"
