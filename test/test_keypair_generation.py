import binascii
import pytest
from eddsa.keys.ed25519_keypair import Ed25519Keypair
from urllib.request import urlopen, Request
from pathlib import Path


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
