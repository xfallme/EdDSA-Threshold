import hashlib


def sha512(data: bytes) -> bytes:
    """Compute SHA-512 hash of the input data."""
    return hashlib.sha512(data).digest()
