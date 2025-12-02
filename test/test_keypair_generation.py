import binascii
import pytest
from eddsa.keys.ed25519_keypair import Ed25519Keypair
from urllib.request import urlopen, Request
from pathlib import Path

from eddsa.keys.ed448_keypair import Ed448Keypair


def case_ed25519_test_vectors_cr_yp_to() -> list[str]:
    # Use http://ed25519.cr.yp.to/python/sign.input as input
    cache_dir = Path(__file__).resolve().parent / "downloads"
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache_file = cache_dir / "sign.input"

    if not cache_file.exists():
        url = "http://ed25519.cr.yp.to/python/sign.input"
        req = Request(url)
        with urlopen(req) as resp:
            content = resp.read().decode("ascii")
        cache_file.write_text(content, encoding="ascii")
    else:
        content = cache_file.read_text(encoding="ascii")

    lines = [ln for ln in content.splitlines() if ln and not ln.startswith("#")]

    return lines


def case_ed448_test_vectors_rfc8032() -> list[str]:
    lines = [
        "6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b:5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180",  # Blank
        "c4eab05d357007c632f3dbb48489924d552b08fe0c353a0d4a1f00acda2c463afbea67c5e8d2877c5e3bc397a659949ef8021e954e0a12274e:43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c0866aea01eb00742802b8438ea4cb82169c235160627b4c3a9480",  # 1 Octet
    ]

    return lines


@pytest.mark.parametrize("lines", [case_ed25519_test_vectors_cr_yp_to()], ids=["Ed25519 Test Vectors from cr.yp.to"])
def test_keypair_generation_ed25519(lines, request):
    print(f"Running with {len(lines)} inputs for test '{request.node.callspec.id}'")
    for line in lines:
        x = line.split(':')
        # First 64 hex chars are the secret key, the rest is the public key
        sk = binascii.unhexlify(x[0][0:64])

        keypair = Ed25519Keypair.from_private_bytes(sk)
        pk = keypair.public_bytes()

        assert x[0] == binascii.hexlify(sk + pk).decode('ascii')
        assert x[1] == binascii.hexlify(pk).decode('ascii')


@pytest.mark.parametrize("lines", [case_ed448_test_vectors_rfc8032()], ids=["Ed448 Test Vectors from RFC8032"])
def test_keypair_generation_ed448(lines, request):
    print(f"Running with {len(lines)} inputs for test '{request.node.callspec.id}'")
    for line in lines:
        x = line.split(':')

        sk = binascii.unhexlify(x[0])

        keypair = Ed448Keypair.from_private_bytes(sk)
        pk = keypair.public_bytes()

        assert x[0] == binascii.hexlify(sk).decode('ascii')
        assert x[1] == binascii.hexlify(pk).decode('ascii')
