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

def case_ed25519ctx_test_vectors_rfc8032() -> list[str]:
    """Manually defined test vectors from RFC 8032, 7.2"""
    lines = [
        # Secret Key:Public Key:Message:Context:Signature
        #foo
        "0305334e381af78f141cb666f6199f57bc3495335a256a95bd2a55bf546663f6:dfc9425e4f968f7f0c29f0259cf5f9aed6851c2bb4ad8bfb860cfee0ab248292:f726936d19c800494e3fdaff20b276a8:666f6f:55a4cc2f70a54e04288c5f4cd1e45a7bb520b36292911876cada7323198dd87a8b36950b95130022907a7fb7c4e9b2d5f6cca685a587b4b21f4b888e4e7edb0d",
        #bar
        "0305334e381af78f141cb666f6199f57bc3495335a256a95bd2a55bf546663f6:dfc9425e4f968f7f0c29f0259cf5f9aed6851c2bb4ad8bfb860cfee0ab248292:f726936d19c800494e3fdaff20b276a8:626172:fc60d5872fc46b3aa69f8b5b4351d5808f92bcc044606db097abab6dbcb1aee3216c48e8b3b66431b5b186d1d28f8ee15a5ca2df6668346291c2043d4eb3e90d",
        #foo2
        "0305334e381af78f141cb666f6199f57bc3495335a256a95bd2a55bf546663f6:dfc9425e4f968f7f0c29f0259cf5f9aed6851c2bb4ad8bfb860cfee0ab248292:508e9e6882b979fea900f62adceaca35:666f6f:8b70c1cc8310e1de20ac53ce28ae6e7207f33c3295e03bb5c0732a1d20dc64908922a8b052cf99b7c4fe107a5abb5b2c4085ae75890d02df26269d8945f84b0b",
        #foo3
        "ab9c2853ce297ddab85c993b3ae14bcad39b2c682beabc27d6d4eb20711d6560:0f1d1274943b91415889152e893d80e93275a1fc0b65fd71b4b0dda10ad7d772:f726936d19c800494e3fdaff20b276a8:666f6f:21655b5f1aa965996b3f97b3c849eafba922a0a62992f73b3d1b73106a84ad85e9b86a7b6005ea868337ff2d20a7f5fbd4cd10b0be49a68da2b2e0dc0ad8960f"
    ]
    
    return lines

def case_ed448_test_vectors_rfc8032() -> list[str]:
    """Manually defined test vectors from RFC 8032, 7.4"""
    lines = [
        "6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b:5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180",  # Blank
        "c4eab05d357007c632f3dbb48489924d552b08fe0c353a0d4a1f00acda2c463afbea67c5e8d2877c5e3bc397a659949ef8021e954e0a12274e:43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c0866aea01eb00742802b8438ea4cb82169c235160627b4c3a9480",  # 1 Octet
    ]

    return lines
